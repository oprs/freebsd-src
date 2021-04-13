/* vi:set ts=8: */

/*
 * if_bng.c - driver for RG Net's Broadband Network Gateway interface.
 * Based on if_vlan.c .
 */

/*-
 * Copyright 1998 Massachusetts Institute of Technology
 * Copyright 2012 ADARA Networks, Inc.
 * Copyright 2017 Dell EMC Isilon
 *
 * Portions of this software were developed by Robert N. M. Watson under
 * contract to ADARA Networks, Inc.
 *
 * Permission to use, copy, modify, and distribute this software and
 * its documentation for any purpose and without fee is hereby
 * granted, provided that both the above copyright notice and this
 * permission notice appear in all copies, that both the above
 * copyright notice and this permission notice appear in all
 * supporting documentation, and that the name of M.I.T. not be used
 * in advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.  M.I.T. makes
 * no representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied
 * warranty.
 *
 * THIS SOFTWARE IS PROVIDED BY M.I.T. ``AS IS''.  M.I.T. DISCLAIMS
 * ALL EXPRESS OR IMPLIED WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. IN NO EVENT
 * SHALL M.I.T. BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/eventhandler.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/module.h>
#include <sys/rmlock.h>
#include <sys/priv.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/limits.h>
#include <sys/proc.h>
#include <sys/sx.h>
#include <sys/taskqueue.h>

#include <net/bpf.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/if_clone.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/if_vlan_var.h>
#include <net/vnet.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include "if_bng.h"

#define IFT_BNG IFT_L2VLAN

#define BNG_FLAGS_DVLAN    0x0001 /* dynamic VLANs active on this interface */

#define BNG_DVLAN_SET(ifp) ((ifp)->if_ispare[3] |=  BNG_FLAGS_DVLAN)
#define BNG_DVLAN_CLR(ifp) ((ifp)->if_ispare[3] &= ~BNG_FLAGS_DVLAN)
#define BNG_DVLAN_HAS(ifp) ((ifp)->if_ispare[3] &   BNG_FLAGS_DVLAN)

#define BNG_IFFLAGS 0

#define UP_AND_RUNNING(ifp) \
    ((ifp)->if_flags & IFF_UP && (ifp)->if_drv_flags & IFF_DRV_RUNNING)

#define BNG_LOG(lvl, ...) \
	do {                                 \
		if ((lvl) <= bng_dbg)        \
			printf(__VA_ARGS__); \
	} while(0)

#define BNG_LOG_DVE(lvl, pfx, dve) \
	do {                                             \
		uint8_t *a = (dve)->dve_haddr;           \
		int dt = dve->dve_expat - BNG_TICKS;     \
		BNG_LOG(lvl, pfx " %6D vid:%d ttl:%d\n", \
		       a, ":", (dve)->dve_vid, dt/BNG_HZ); \
	} while(0)

#define BNG_LOG_ADD(dve) BNG_LOG_DVE(2, "+", dve)
#define BNG_LOG_DEL(dve) BNG_LOG_DVE(2, "-", dve)
#define BNG_LOG_MOD(dve) BNG_LOG_DVE(2, "=", dve)
#define BNG_LOG_GET(dve) BNG_LOG_DVE(3, "?", dve)

#define HASH_WIDTH 8
#define HASH_SIZE  (1 << (HASH_WIDTH))
#define HASH_MASK  (HASH_SIZE - 1)

#define DVLAN_HASH(haddr) \
	((haddr)[ETHER_ADDR_LEN-1] & HASH_MASK)

#define HADDR_EQ(a,b) \
	(((a)[ETHER_ADDR_LEN-1] == (b)[ETHER_ADDR_LEN-1]) && \
	 (memcmp((a),(b),ETHER_ADDR_LEN-1) == 0))

#define SLOT_WLOCK(_ds)    mtx_lock(&((_ds)->lock))
#define SLOT_WUNLOCK(_ds)  mtx_unlock(&((_ds)->lock))
#define SLOT_RLOCK(_ds)    SLOT_WLOCK(_ds)
#define SLOT_RUNLOCK(_ds)  SLOT_WUNLOCK(_ds)

struct ifvlantrunk {
	struct ifnet     *parent;  /* parent interface of this trunk */
	struct bng_softc *sc;
	struct mtx        lock;
	int               refcnt;
};

struct bng_softc {
	struct ifvlantrunk *bng_trunk;
	struct ifnet *bng_ifp;
#define	TRUNK(sc)  ((sc)->bng_trunk)
#define	PARENT(sc) (TRUNK(sc)->parent)
	int           bng_pflags;    /* special flags we have set on parent */
	int           bng_capenable;
	int           bng_encaplen;  /* encapsulation length */
	int           bng_mtufudge;  /* MTU fudged by this much */
	int           bng_mintu;     /* min transmission unit */
	uint8_t       bng_pcp;       /* Priority Code Point (PCP). */
	struct task   lladdr_task;
};

/* Special flags we should propagate to parent. */
static struct {
	int flag;
	int (*func)(struct ifnet *, int);
} bng_pflags[] = {
	{IFF_PROMISC, ifpromisc},
	{IFF_ALLMULTI, if_allmulti},
	{0, NULL}
};

static const char bngname[] = "bng";
#define BNGNAME_LEN (sizeof(bngname) - 1)

static MALLOC_DEFINE(M_BNG, bngname, "Broadband Network Gateway Interface");

/* VLAN state change events */
typedef void (*bng_config_fn)(void *, struct ifnet *);
typedef void (*bng_unconfig_fn)(void *, struct ifnet *);
EVENTHANDLER_DECLARE(bng_config, bng_config_fn);
EVENTHANDLER_DECLARE(bng_unconfig, bng_unconfig_fn);

static eventhandler_tag ifdetach_tag;
static eventhandler_tag iflladdr_tag;

/*
 * if_vlan uses two module-level synchronizations primitives to allow concurrent
 * modification of vlan interfaces and (mostly) allow for vlans to be destroyed
 * while they are being used for tx/rx. To accomplish this in a way that has
 * acceptable performance and cooperation with other parts of the network stack
 * there is a non-sleepable epoch(9) and an sx(9).
 *
 * The performance-sensitive paths that warrant using the epoch(9) are
 * bng_transmit and bng_input. Both have to check for the vlan interface's
 * existence using if_vlantrunk, and being in the network tx/rx paths the use
 * of an epoch(9) gives a measureable improvement in performance.
 *
 * The reason for having an sx(9) is mostly because there are still areas that
 * must be sleepable and also have safe concurrent access to a vlan interface.
 * Since the sx(9) exists, it is used by default in most paths unless sleeping
 * is not permitted, or if it is not clear whether sleeping is permitted.
 *
 */
#define _BNG_SX_ID bng_sx

static struct sx _BNG_SX_ID;

#define BNG_LOCKING_INIT()	{ BNG_LOG(9, "BNG_LOCKING_INIT()\n"); sx_init(&_BNG_SX_ID, "bng_sx"); }
#define BNG_LOCKING_DESTROY()	{ BNG_LOG(9, "BNG_LOCKING_DESTROY()\n"); sx_destroy(&_BNG_SX_ID); }

#define BNG_RLOCK(et)		NET_EPOCH_ENTER(et);
#define BNG_RUNLOCK(et)		NET_EPOCH_EXIT(et);
#define BNG_RLOCK_ASSERT()	MPASS(in_epoch(net_epoch_preempt))

#define BNG_SLOCK()		{ BNG_LOG(9, "BNG_SLOCK()\n"); sx_slock(&_BNG_SX_ID); }
#define BNG_SUNLOCK()		{ sx_sunlock(&_BNG_SX_ID); BNG_LOG(9, "BNG_SUNLOCK()\n"); }
#define BNG_XLOCK()		{ BNG_LOG(9, "BNG_XLOCK()\n"); sx_xlock(&_BNG_SX_ID); }
#define BNG_XUNLOCK()		{ sx_xunlock(&_BNG_SX_ID); BNG_LOG(9, "BNG_XUNLOCK()\n"); }
#define BNG_SLOCK_ASSERT()	sx_assert(&_BNG_SX_ID, SA_SLOCKED)
#define BNG_XLOCK_ASSERT()	sx_assert(&_BNG_SX_ID, SA_XLOCKED)
#define BNG_SXLOCK_ASSERT()	sx_assert(&_BNG_SX_ID, SA_LOCKED)

#define TRUNK_LOCK_INIT(t)	mtx_init(&(t)->lock, bngname, NULL, MTX_DEF)
#define TRUNK_LOCK_DESTROY(t)	mtx_destroy(&(t)->lock)
#define TRUNK_RLOCK(t)		NET_EPOCH_ENTER()
#define TRUNK_WLOCK(t)		mtx_lock(&(t)->lock)
#define TRUNK_RUNLOCK(t)	NET_EPOCH_EXIT();
#define TRUNK_WUNLOCK(t)	mtx_unlock(&(t)->lock)
#define TRUNK_RLOCK_ASSERT(t)	MPASS(in_epoch(net_epoch_preempt))
#define TRUNK_LOCK_ASSERT(t)	MPASS(in_epoch(net_epoch_preempt) || mtx_owned(&(t)->lock))
#define TRUNK_WLOCK_ASSERT(t)	mtx_assert(&(t)->lock, MA_OWNED);

/* -------- */

#if 0
#define BNG_TICKS ticks
#define BNG_HZ    hz
#else
#define BNG_TICKS time_uptime
#define BNG_HZ    1
#endif

#define BNG_HWIDTH 8
#define BNG_HSIZE  (1 << (BNG_HWIDTH))
#define BNG_HMASK  (BNG_HSIZE - 1)

enum {
	BNG_POL_NONE = 0x0000,
	BNG_POL_ARP  = 0x0001,
	BNG_POL_DHCP = 0x0002
};

#define BNG_DEFAULT_DBG 1
#define BNG_DEFAULT_POL BNG_POL_ARP
#define BNG_DEFAULT_TTL 1200

#define BNG_HASH(haddr) \
	((haddr)[ETHER_ADDR_LEN-1] & BNG_HMASK)

#define HADDR_EQ(a,b) \
	(((a)[ETHER_ADDR_LEN-1] == (b)[ETHER_ADDR_LEN-1]) && \
	 (memcmp((a),(b),ETHER_ADDR_LEN-1) == 0))

static struct sysctl_ctx_list clist;
static struct sysctl_oid *bng_oid;

static int bng_dbg;
static int bng_pol;
static int bng_ttl;

#define DVE_FLAGS_MASK  0x0f
#define DVE_FLAG_STATIC 0x01

#define DVE_IS_STATIC(dve) \
	(((dve)->dve_flags & DVE_FLAG_STATIC) != 0)

#define SLOT_WLOCK(_ds)		mtx_lock(&((_ds)->lock))
#define SLOT_WUNLOCK(_ds)	mtx_unlock(&((_ds)->lock))
#define SLOT_RLOCK(_ds)		SLOT_WLOCK(_ds)
#define SLOT_RUNLOCK(_ds)	SLOT_WUNLOCK(_ds)

struct dv_entry {
	TAILQ_ENTRY(dv_entry) entries;
	struct bng_entry be;
#define dve_creat be.be_creat
#define dve_updat be.be_updat
#define dve_expat be.be_expat
#define dve_flags be.be_flags
#define dve_haddr be.be_haddr
#define dve_proto be.be_proto
#define dve_vid   be.be_vid
};

TAILQ_HEAD(dvs_head, dv_entry);

struct dv_slot {
	struct dvs_head head;
	struct mtx lock;
};

struct dv_cache {
	struct dv_slot *slots;
};

static void dvs_timeout		(struct dv_slot *);
static void timeout_handler	(void *);

static void bng_cache_init	(void);
static void bng_cache_cleanup	(void);
static int  bng_cache_dump	(void *, size_t);

static int  bng_cache_set	(const uint8_t *, uint16_t, uint16_t, uint32_t, bool);
static int  bng_cache_get	(const uint8_t *, uint16_t *, uint16_t *);
static int  bng_cache_del	(const uint8_t *);

static void trunk_destroy	(struct ifvlantrunk *trunk);

static void bng_init		(void *);
static int  bng_ioctl		(struct ifnet *, u_long, caddr_t);
static void bng_qflush		(struct ifnet *);
static int  bng_transmit	(struct ifnet *, struct mbuf *);
static void bng_altq_start	(struct ifnet *ifp);
static int  bng_altq_transmit	(struct ifnet *ifp, struct mbuf *m);
static void bng_input		(struct ifnet *, struct mbuf *);
static void bng_link_state	(struct ifnet *);
static void bng_trunk_cap	(struct ifnet *);
#ifdef RATELIMIT
static int  bng_snd_tag_alloc	(struct ifnet *, union if_snd_tag_alloc_params *, struct m_snd_tag **);
#endif
static int  bng_setflag		(struct ifnet *, int, int, int (*)(struct ifnet *, int));
static int  bng_setflags	(struct ifnet *, int);
static void bng_unconfig	(struct ifnet *);
static void bng_unconfig_locked	(struct ifnet *, int);
static int  bng_config		(struct bng_softc *, struct ifnet *);
static void bng_capabilities	(struct bng_softc *);

static int  bng_clone_match	(struct if_clone *, const char *);
static int  bng_clone_create	(struct if_clone *, char *, size_t, caddr_t);
static int  bng_clone_destroy	(struct if_clone *, struct ifnet *);

static void bng_ifdetach	(void *, struct ifnet *);
static void bng_iflladdr	(void *, struct ifnet *);
static void bng_lladdr_fn	(void *, int);

static int  bng_sysctl_init	(void);
static int  bng_sysctl_cleanup	(void);
static int  bng_modevent	(module_t, int, void *);

extern void (*vlan_input_p)		(struct ifnet *, struct mbuf *);
static void (*vlan_input_p_orig)	(struct ifnet *, struct mbuf *);

extern void (*vlan_link_state_p)	(struct ifnet *ifp);
static void (*vlan_link_state_p_orig)	(struct ifnet *ifp);

extern void (*vlan_trunk_cap_p)		(struct ifnet *ifp);
static void (*vlan_trunk_cap_p_orig)	(struct ifnet *ifp);

static struct dv_cache	cache;
static struct callout	callout;

static struct if_clone	*bng_cloner;
VNET_DEFINE_STATIC(struct if_clone *, bng_cloner);
#define V_bng_cloner VNET(bng_cloner)

/*
 * Cache management functions
 */

static void
dvs_timeout(struct dv_slot *dvs)
{
	struct dv_entry *dve;

#if 0
	dve = TAILQ_FIRST(&dvs->head);
	if (dve != NULL) {
		while (dve != NULL) {
			(void)printf("%d ", dve->be.be_expat);
			dve = TAILQ_NEXT(dve, entries);
		}
		(void)printf("\n");
	}
#endif

	SLOT_WLOCK(dvs);
	while (((dve = TAILQ_LAST(&dvs->head, dvs_head)) != NULL)
	    && (dve->dve_expat <= BNG_TICKS)) {
		TAILQ_REMOVE(&dvs->head, dve, entries);
		BNG_LOG_DEL(dve);
		free(dve, M_BNG);
	}
	SLOT_WUNLOCK(dvs);
}

static void
timeout_handler(void *x)
{
	int i;

	(void)x;
	for (i = 0; i < HASH_SIZE; i++)
		dvs_timeout(&cache.slots[i]);
	callout_schedule(&callout, 3*hz);
}

static void
bng_cache_init()
{
	struct dv_slot *dvs;
	int i;

	cache.slots = malloc(sizeof(struct dv_slot) * HASH_SIZE, M_BNG, M_WAITOK);
	/* init cache */
	for (i = 0; i < HASH_SIZE; i++) {
		dvs = &cache.slots[i];
		TAILQ_INIT(&dvs->head);
		mtx_init(&dvs->lock, "bng_dvs", NULL, MTX_DEF|MTX_NEW);
	}
	callout_init(&callout, 1);
	callout_reset(&callout, 3*hz, timeout_handler, NULL);
}

static void
bng_cache_cleanup(void)
{
	struct dv_slot   *dvs;
	struct dv_entry  *dve;
	int i;

	(void)callout_drain(&callout);
	for (i = 0; i < HASH_SIZE; i++) {
		dvs = &cache.slots[i];
		SLOT_WLOCK(dvs);
		while ((dve = TAILQ_FIRST(&dvs->head)) != NULL) {
			TAILQ_REMOVE(&dvs->head, dve, entries);
			BNG_LOG_DEL(dve);
			free(dve, M_BNG);
		}
		SLOT_WUNLOCK(dvs);
		mtx_destroy(&dvs->lock);
	}
	free(cache.slots, M_BNG);
}

static int
bng_cache_set(const uint8_t *haddr, uint16_t vid, uint16_t proto, uint32_t flags, bool refresh)
{
	struct dv_slot  *dvs;
	struct dv_entry *dve;

	dvs = &cache.slots[DVLAN_HASH(haddr)];
	SLOT_WLOCK(dvs);
	TAILQ_FOREACH(dve, &dvs->head, entries) {
		if (HADDR_EQ(dve->dve_haddr, haddr))
			break;
	}

	if (dve == NULL) {
		/* L2 address is unknown: create a new entry */
		dve = malloc(sizeof(struct dv_entry), M_BNG, M_NOWAIT);
		if (dve == NULL) {
			SLOT_WUNLOCK(dvs);
			return ENOMEM;
		}
		(void)memcpy(dve->dve_haddr, haddr, ETHER_ADDR_LEN);
		dve->dve_vid = vid;
		dve->dve_proto = proto;
		dve->dve_flags = flags & DVE_FLAGS_MASK;
		dve->dve_creat = BNG_TICKS;
		if (flags & DVE_FLAG_STATIC)
			dve->dve_expat = INT_MAX;
		else
			dve->dve_expat = BNG_TICKS+(bng_ttl*BNG_HZ);
		BNG_LOG_ADD(dve);
		TAILQ_INSERT_HEAD(&dvs->head, dve, entries);
	} else {
		/* Existing entry: see if we need to refresh it */
		if (refresh) {
			/* Move entry to the front if not already there */
			if (dve != TAILQ_FIRST(&dvs->head)) {
				TAILQ_REMOVE(&dvs->head, dve, entries);
				TAILQ_INSERT_HEAD(&dvs->head, dve, entries);
			}
			/* Give it more life time */
			if (!DVE_IS_STATIC(dve))
				dve->dve_expat = BNG_TICKS+(bng_ttl*BNG_HZ);
		}
		if ((flags & DVE_FLAG_STATIC) || (!DVE_IS_STATIC(dve))) {
			/* The VLAN ID for this entry may have changed, update it */
			if ((dve->dve_vid != vid) || (dve->dve_proto != proto)) {
				dve->dve_vid   = vid;
				dve->dve_proto = proto;
				BNG_LOG_MOD(dve);
			}
		}
	}
	dve->dve_updat = BNG_TICKS;
	SLOT_WUNLOCK(dvs);

	return 0;
}

static int
bng_cache_get(const uint8_t *haddr, uint16_t *pvid, uint16_t *pproto)
{
	struct dv_slot  *dvs;
	struct dv_entry *dve;

	dvs = &cache.slots[DVLAN_HASH(haddr)];
	SLOT_RLOCK(dvs);
	TAILQ_FOREACH(dve, &dvs->head, entries) {
		if (HADDR_EQ(dve->dve_haddr, haddr)) {
			*pvid   = dve->dve_vid;
			*pproto = dve->dve_proto;
			break;
		}
	}
	SLOT_RUNLOCK(dvs);

	if (dve == NULL)
		return ENOENT;

	BNG_LOG_GET(dve);

	return 0;
}

static int
bng_cache_del(const uint8_t *haddr)
{
	struct dv_slot  *dvs;
	struct dv_entry *dve, *tmp;

	dvs = &cache.slots[DVLAN_HASH(haddr)];
	SLOT_WLOCK(dvs);
	TAILQ_FOREACH_SAFE(dve, &dvs->head, entries, tmp) {
		if (HADDR_EQ(dve->dve_haddr, haddr)) {
			TAILQ_REMOVE(&dvs->head, dve, entries);
			BNG_LOG_DEL(dve);
			free(dve, M_BNG);
			break;
		}
	}
	SLOT_WUNLOCK(dvs);

	if (dve == NULL)
		return ENOENT;

	return 0;
}

static int
bng_cache_dump(void *x, size_t sz)
{
	struct dv_slot  *dvs;
	struct dv_entry *dve;
	struct bng_header bh;
	int i, n, nmax;

	if ((x == NULL) || (sz < sizeof(struct bng_header)))
		return EINVAL;

	nmax = (sz - sizeof(struct bng_header)) / sizeof(struct bng_entry);
	uint8_t *ubase = (uint8_t*)x + sizeof(struct bng_header);
	for (i = 0, n = 0; (i < HASH_SIZE) && (n < nmax); i++) {
		dvs = &cache.slots[i];
		SLOT_RLOCK(dvs);
		TAILQ_FOREACH(dve, &dvs->head, entries) {
			if (copyout(&dve->be, ubase + n * sizeof(struct bng_entry),
				sizeof(struct bng_entry)) != 0) {
				SLOT_RUNLOCK(dvs);
				return EIO;
			}
			n++;
		}
		SLOT_RUNLOCK(dvs);
	}

	if (n >= nmax)
		BNG_LOG(1, "%s: too many entries\n", __func__);

	bh.bh_ticks = BNG_TICKS;
	bh.bh_hz    = BNG_HZ;
	bh.bh_nelem = n;

	if (copyout(&bh, x, sizeof(bh)) != 0)
		return EIO;

	return 0;
}

/*
 */

static void
trunk_destroy(struct ifvlantrunk *trunk)
{
	BNG_XLOCK_ASSERT();

	trunk->parent->if_vlantrunk = NULL;
	TRUNK_LOCK_DESTROY(trunk);
	if_rele(trunk->parent);
	free(trunk, M_BNG);
}

/*
 * A handler for parent interface link layer address changes.
 * If the parent interface link layer address is changed we
 * should also change it on all children vlans.
 */
static void
bng_iflladdr(void *arg __unused, struct ifnet *ifp)
{
	struct epoch_tracker et;
	struct bng_softc *sc;
	struct ifnet *bng_ifp;
	struct ifvlantrunk *trunk;
	struct sockaddr_dl *sdl;

	/* Need the rmlock since this is run on taskqueue_swi. */
	BNG_RLOCK(et);
	trunk = ifp->if_vlantrunk;
	if (trunk == NULL) {
		BNG_RUNLOCK(et);
		return;
	}

	/*
	 * OK, it's a trunk.  Loop over and change all vlan's lladdrs on it.
	 * We need an exclusive lock here to prevent concurrent SIOCSIFLLADDR
	 * ioctl calls on the parent garbling the lladdr of the child vlan.
	 */
	TRUNK_WLOCK(trunk);
	sc = trunk->sc;
	bng_ifp = sc->bng_ifp;
	bcopy(IF_LLADDR(ifp), IF_LLADDR(bng_ifp),
	    ifp->if_addrlen);
	sdl = (struct sockaddr_dl *)bng_ifp->if_addr->ifa_addr;
	sdl->sdl_alen = ifp->if_addrlen;
	taskqueue_enqueue(taskqueue_thread, &sc->lladdr_task);
	TRUNK_WUNLOCK(trunk);
	BNG_RUNLOCK(et);
}

/*
 * A handler for network interface departure events.
 * Track departure of trunks here so that we don't access invalid
 * pointers or whatever if a trunk is ripped from under us, e.g.,
 * by ejecting its hot-plug card.  However, if an ifnet is simply
 * being renamed, then there's no need to tear down the state.
 */
static void
bng_ifdetach(void *arg __unused, struct ifnet *ifp)
{
	struct bng_softc *sc;
	struct ifvlantrunk *trunk;

	/* If the ifnet is just being renamed, don't do anything. */
	if (ifp->if_flags & IFF_RENAMING)
		return;
	BNG_XLOCK();
	trunk = ifp->if_vlantrunk;
	if (trunk == NULL) {
		BNG_XUNLOCK();
		return;
	}

	/*
	 * OK, it's a trunk.  Loop over and detach all vlan's on it.
	 * Check trunk pointer after each bng_unconfig() as it will
	 * free it and set to NULL after the last vlan was detached.
	 */
	sc = trunk->sc;
	bng_unconfig_locked(sc->bng_ifp, 1);

	/* Trunk should have been destroyed in bng_unconfig(). */
	KASSERT(ifp->if_vlantrunk == NULL, ("%s: purge failed", __func__));
	BNG_XUNLOCK();
}

static int
bng_sysctl_init()
{
	sysctl_ctx_init(&clist);
	bng_oid = SYSCTL_ADD_NODE(&clist, SYSCTL_STATIC_CHILDREN(_net),
		OID_AUTO, "bng", CTLFLAG_RW, 0, "BNG module tree");
	if (bng_oid == NULL)
		return EINVAL;

	SYSCTL_ADD_INT(&clist, SYSCTL_CHILDREN(bng_oid),
		OID_AUTO, "debug", CTLFLAG_RW, &bng_dbg, 0, "BNG module debug level");

	SYSCTL_ADD_INT(&clist, SYSCTL_CHILDREN(bng_oid),
		OID_AUTO, "policy", CTLFLAG_RW, &bng_pol, 0, "Filter policy (0: none, 1: ARP");

	SYSCTL_ADD_INT(&clist, SYSCTL_CHILDREN(bng_oid),
		OID_AUTO, "ttl", CTLFLAG_RW, &bng_ttl, 0, "TTL for cache entries (seconds)");

	return 0;
}

static int
bng_sysctl_cleanup()
{
	if (sysctl_ctx_free(&clist))
		return ENOTEMPTY;

	return 0;
}

void
bng_hijack_vlan()
{
	KASSERT(vlan_input_p != NULL,("%s: VLAN not loaded", __func__));
	vlan_input_p_orig      = vlan_input_p;
	vlan_input_p           = bng_input;
	vlan_link_state_p_orig = vlan_link_state_p;
	vlan_link_state_p      = bng_link_state;
	vlan_trunk_cap_p_orig  = vlan_trunk_cap_p;
	vlan_trunk_cap_p       = bng_trunk_cap;
	BNG_LOG(1, "bng: active\n");
}

void
bng_restore_vlan()
{
	vlan_input_p      = vlan_input_p_orig;
	vlan_link_state_p = vlan_link_state_p_orig;
	vlan_trunk_cap_p  = vlan_trunk_cap_p_orig;
	BNG_LOG(1, "bng: inactive\n");
}

static int
bng_modevent(module_t mod, int type, void *data)
{
	switch (type) {
	case MOD_LOAD:
		bng_dbg = BNG_DEFAULT_DBG;
		bng_ttl = BNG_DEFAULT_TTL;
		bng_pol = BNG_DEFAULT_POL;
		ifdetach_tag = EVENTHANDLER_REGISTER(ifnet_departure_event,
		    bng_ifdetach, NULL, EVENTHANDLER_PRI_ANY);
		if (ifdetach_tag == NULL)
			return ENOMEM;
		iflladdr_tag = EVENTHANDLER_REGISTER(iflladdr_event,
		    bng_iflladdr, NULL, EVENTHANDLER_PRI_ANY);
		if (iflladdr_tag == NULL)
			return ENOMEM;
		BNG_LOCKING_INIT();
		(void)bng_cache_init();
		(void)bng_sysctl_init();
		//bng_hijack_vlan();
		BNG_LOG(1, "bng: initialized\n");
		break;
	case MOD_UNLOAD:
		EVENTHANDLER_DEREGISTER(iflladdr_event, iflladdr_tag);
		EVENTHANDLER_DEREGISTER(ifnet_departure_event, ifdetach_tag);
		//bng_restore_vlan();
		(void)bng_cache_cleanup();
		(void)bng_sysctl_cleanup();
		//BNG_LOCKING_DESTROY(); XXX
		BNG_LOG(1, "bng: unloaded\n");
		break;
	default:
		return EOPNOTSUPP;
	}
	return 0;
}

static moduledata_t bng_mod = {
	"if_bng",
	bng_modevent,
	0
};

DECLARE_MODULE(if_bng, bng_mod, SI_SUB_PSEUDO, SI_ORDER_ANY);
MODULE_VERSION(if_bng, 1);

static void
vnet_bng_init(const void *unused __unused)
{
	bng_cloner = if_clone_advanced(bngname, 0, bng_clone_match,
		    bng_clone_create, bng_clone_destroy);
	V_bng_cloner = bng_cloner;
}
VNET_SYSINIT(vnet_bng_init, SI_SUB_PROTO_IFATTACHDOMAIN, SI_ORDER_ANY,
    vnet_bng_init, NULL);

static void
vnet_bng_uninit(const void *unused __unused)
{
	if_clone_detach(V_bng_cloner);
}
VNET_SYSUNINIT(vnet_bng_uninit, SI_SUB_INIT_IF, SI_ORDER_FIRST,
    vnet_bng_uninit, NULL);

static int
bng_clone_match(struct if_clone *ifc, const char *name)
{
	const char *cp;

	if (strncmp(bngname, name, BNGNAME_LEN) != 0)
		return 0;
	for (cp = name + BNGNAME_LEN; *cp != '\0'; cp++) {
		if (*cp < '0' || *cp > '9')
			return 0;
	}

	return 1;
}

static int
bng_clone_create(struct if_clone *ifc, char *name, size_t len, caddr_t params)
{
	char *dp;
	int wildcard;
	int unit;
	int error;
	struct bng_softc *sc;
	struct ifnet *ifp;
	struct ifnet *p;
	struct ifaddr *ifa;
	struct sockaddr_dl *sdl;
	struct bng_req_parent brp;
	static const u_char eaddr[ETHER_ADDR_LEN];	/* 00:00:00:00:00:00 */

	/*
	 * There are 3 (ugh) ways to specify the cloned device:
	 * o pass a parameter block with the clone request.
	 * o specify parameters in the text of the clone device name
	 * o specify no parameters and get an unattached device that
	 *   must be configured separately.
	 * The first technique is preferred; the latter two are
	 * supported for backwards compatibility.
	 *
	 * XXXRW: Note historic use of the word "tag" here.  New ioctls may be
	 * called for.
	 */
	if (params) {
		error = copyin(params, &brp, sizeof(brp));
		if (error)
			return error;
		p = ifunit_ref(brp.brp_parent);
		if (p == NULL)
			return ENXIO;
		error = ifc_name2unit(name, &unit);
		if (error != 0) {
			if_rele(p);
			return error;
		}
		wildcard = (unit < 0);
	} else {
		p = NULL;
		error = ifc_name2unit(name, &unit);
		if (error != 0)
			return error;

		wildcard = (unit < 0);
	}

	error = ifc_alloc_unit(ifc, &unit);
	if (error != 0) {
		if (p != NULL)
			if_rele(p);
		return error;
	}

	/* In the wildcard case, we need to update the name. */
	if (wildcard) {
		for (dp = name; *dp != '\0'; dp++);
		if (snprintf(dp, len - (dp-name), "%d", unit) >
		    len - (dp-name) - 1) {
			panic("%s: interface name too long", __func__);
		}
	}

	sc = malloc(sizeof(struct bng_softc), M_BNG, M_WAITOK | M_ZERO);
	ifp = sc->bng_ifp = if_alloc(IFT_ETHER);
	if (ifp == NULL) {
		ifc_free_unit(ifc, unit);
		free(sc, M_BNG);
		if (p != NULL)
			if_rele(p);
		return ENOSPC;
	}
	ifp->if_softc = sc;
	/*
	 * Set the name manually rather than using if_initname because
	 * we don't conform to the default naming convention for interfaces.
	 * XXX [bng] don't we ?
	 */
	strlcpy(ifp->if_xname, name, IFNAMSIZ);
	ifp->if_dname         = bngname;
	ifp->if_dunit         = unit;
	ifp->if_init          = bng_init;
	ifp->if_start         = bng_altq_start;
	ifp->if_transmit      = bng_altq_transmit;
	IFQ_SET_MAXLEN(&ifp->if_snd[0], ifqmaxlen);
	ifp->if_snd[0].ifq_drv_maxlen = 0;
	IFQ_SET_READY(&ifp->if_snd[0]);
	ifp->if_qflush        = bng_qflush;
	ifp->if_ioctl         = bng_ioctl;
#ifdef RATELIMIT
	ifp->if_snd_tag_alloc = bng_snd_tag_alloc;
#endif
	ifp->if_flags         = BNG_IFFLAGS;
	ether_ifattach(ifp, eaddr);
	/* Now undo some of the damage... */
	ifp->if_baudrate      = 0;
	ifp->if_type          = IFT_BNG;
	ifp->if_hdrlen        = ETHER_VLAN_ENCAP_LEN;
	ifa = ifp->if_addr;
	sdl = (struct sockaddr_dl *)ifa->ifa_addr;
	sdl->sdl_type = IFT_L2VLAN;

	if (p != NULL) {
		error = bng_config(sc, p);
		if_rele(p);
		if (error != 0) {
			/*
			 * Since we've partially failed, we need to back
			 * out all the way, otherwise userland could get
			 * confused.  Thus, we destroy the interface.
			 */
			ether_ifdetach(ifp);
			bng_unconfig(ifp);
			if_free(ifp);
			ifc_free_unit(ifc, unit);
			free(sc, M_BNG);

			return error;
		}
	}

	return 0;
}

static int
bng_clone_destroy(struct if_clone *ifc, struct ifnet *ifp)
{
	struct bng_softc *sc = ifp->if_softc;

	IFQ_PURGE(&ifp->if_snd[0]);
	ether_ifdetach(ifp);	/* first, remove it from system-wide lists */
	bng_unconfig(ifp);	/* now it can be unconfigured and freed */
	/*
	 * We should have the only reference to the sc now, so we can now
	 * drain any remaining lladdr task before freeing the ifnet and the
	 * ifvlan.
	 */
	taskqueue_drain(taskqueue_thread, &sc->lladdr_task);
	NET_EPOCH_WAIT();
	if_free(ifp);
	free(sc, M_BNG);
	ifc_free_unit(ifc, ifp->if_dunit);

	return 0;
}

static void
bng_init(void *foo __unused)
{
}

/*
 * The if_transmit method for bng(4) interface.
 */
static int
bng_transmit(struct ifnet *ifp, struct mbuf *m)
{
	struct epoch_tracker et;
	struct ether_header *eh;
	struct bng_softc *sc;
	struct ifnet *p;
	int error, len, mcast;
	uint16_t vid, proto;

	BNG_RLOCK(et);
	sc = ifp->if_softc;
	if (TRUNK(sc) == NULL) {
		if_inc_counter(ifp, IFCOUNTER_OERRORS, 1);
		BNG_RUNLOCK(et);
		m_freem(m);
		BNG_LOG(3, "%s: drop case #1\n", __func__);
		return ENETDOWN;
	}
	p = PARENT(sc);
	len = m->m_pkthdr.len;
	mcast = (m->m_flags & (M_MCAST | M_BCAST)) ? 1 : 0; // XXX disable mcast

	BPF_MTAP(ifp, m);

	/*
	 * Do not run parent's if_transmit() if the parent is not up,
	 * or parent's driver will cause a system crash.
	 */
	if (!UP_AND_RUNNING(p)) {
		if_inc_counter(ifp, IFCOUNTER_OERRORS, 1);
		BNG_RUNLOCK(et);
		m_freem(m);
		return ENETDOWN;
	}

	/* Unknown dest. L2 address: drop */
	eh = mtod(m, struct ether_header*);
	if (bng_cache_get(eh->ether_dhost, &vid, &proto) != 0) {
		if_inc_counter(ifp, IFCOUNTER_OERRORS, 1);
		BNG_RUNLOCK(et);
		m_freem(m);
		BNG_LOG(3, "%s: drop case #2\n", __func__);
		return EHOSTUNREACH;
	}

	m = ether_vlanencap_proto(m, vid, proto);
	if (m == NULL) {
		BNG_RUNLOCK(et);
		BNG_LOG(3, "%s: drop case #3\n", __func__);
		return ENOMEM;
	}

	/*
	 * Send it, precisely as ether_output() would have.
	 */
	error = (p->if_transmit)(p, m);
	if (error == 0) {
		if_inc_counter(ifp, IFCOUNTER_OPACKETS, 1);
		if_inc_counter(ifp, IFCOUNTER_OBYTES, len);
		if_inc_counter(ifp, IFCOUNTER_OMCASTS, mcast);
	} else
		if_inc_counter(ifp, IFCOUNTER_OERRORS, 1);
	BNG_RUNLOCK(et);
	return error;
}

static void
bng_altq_start(struct ifnet *ifp)
{
	struct ifaltq *ifq = &ifp->if_snd[0];
	struct mbuf *m;

	IFQ_LOCK(ifq);
	IFQ_DEQUEUE_NOLOCK(ifq, m);
	while (m != NULL) {
		bng_transmit(ifp, m);
		IFQ_DEQUEUE_NOLOCK(ifq, m);
	}
	IFQ_UNLOCK(ifq);
}

static int
bng_altq_transmit(struct ifnet *ifp, struct mbuf *m)
{
	int err;

	if (ALTQ_IS_ENABLED(&ifp->if_snd[0])) {
		IFQ_ENQUEUE(&ifp->if_snd[0], m, err);
		if (err == 0)
			bng_altq_start(ifp);
	} else
		err = bng_transmit(ifp, m);

	return (err);
}

/*
 * The ifp->if_qflush entry point for vlan(4) is a no-op.
 */
static void
bng_qflush(struct ifnet *ifp __unused)
{
}

static void
bng_input(struct ifnet *ifp, struct mbuf *m)
{
	struct epoch_tracker et;
	struct ifvlantrunk *trunk;
	struct bng_softc *sc;

	struct ether_header *eh;
	struct ip *ih;
	struct udphdr *uh;
	uint8_t *x;
	int xlen;

	uint16_t vid, tag, proto;
	int refresh;

	if (!BNG_DVLAN_HAS(ifp))
		return vlan_input_p_orig(ifp, m);

	BNG_RLOCK(et);
	trunk = ifp->if_vlantrunk;
	if (trunk == NULL) {
		BNG_RUNLOCK(et);
		m_freem(m);
		return;
	}

	if (m->m_flags & M_VLANTAG) {
		/*
		 * Packet is tagged, but m contains a normal
		 * Ethernet frame; the tag is stored out-of-band.
		 */
		tag = m->m_pkthdr.ether_vtag;
		m->m_flags &= ~M_VLANTAG;
		proto = ETHERTYPE_VLAN;
	} else {
		struct ether_vlan_header *evl;

		/*
		 * Packet is tagged in-band as specified by 802.1q.
		 */
		switch (ifp->if_type) {
		case IFT_ETHER:
			if (m->m_len < sizeof(*evl) &&
			    (m = m_pullup(m, sizeof(*evl))) == NULL) {
				if_printf(ifp, "cannot pullup VLAN header\n");
				BNG_RUNLOCK(et);
				return;
			}
			evl   = mtod(m, struct ether_vlan_header *);
			tag   = ntohs(evl->evl_tag);
			proto = ntohs(evl->evl_encap_proto);

			/*
			 * Remove the 802.1q header by copying the Ethernet
			 * addresses over it and adjusting the beginning of
			 * the data in the mbuf.  The encapsulated Ethernet
			 * type field is already in place.
			 */
			bcopy((char *)evl, (char *)evl + ETHER_VLAN_ENCAP_LEN,
			      ETHER_HDR_LEN - ETHER_TYPE_LEN);
			m_adj(m, ETHER_VLAN_ENCAP_LEN);
			break;

		default:
#ifdef INVARIANTS
			panic("%s: %s has unsupported if_type %u",
			      __func__, ifp->if_xname, ifp->if_type);
#endif
			if_inc_counter(ifp, IFCOUNTER_NOPROTO, 1);
			BNG_RUNLOCK(et);
			m_freem(m);
			return;
		}
	}

	/* Update the cache */
	refresh = 0;
	eh = mtod(m, struct ether_header*);

	if (bng_pol == 0) {
		refresh = 1;
	} else {
		switch (eh->ether_type) {
			case htons(ETHERTYPE_ARP):
				if ((bng_pol & BNG_POL_ARP) != 0)
					refresh = 1;
				break;

			case htons(ETHERTYPE_IP):
				if ((bng_pol & BNG_POL_DHCP) == 0)
					break;

				x    = mtod(m, uint8_t*) + sizeof(struct ether_header);
				xlen = m->m_len          - sizeof(struct ether_header);

				if (xlen < (sizeof(struct ip)))
					break;

				ih = (struct ip*)x;
				if (ih->ip_p != IPPROTO_UDP)
					break;

				x    += (ih->ip_hl<<2);
				xlen -= (ih->ip_hl<<2);
				if (xlen < sizeof(struct udphdr))
					break;

				uh = (struct udphdr*)x;
				if (ntohs(uh->uh_dport) == 67)
					refresh = 1;

				break;
		}
	}

	BNG_LOG(8, "%s: refresh: %d, bng_pol: %d\n", __func__, refresh, bng_pol);
	(void)bng_cache_set(eh->ether_shost, tag, proto, 0, refresh);

	vid = EVL_VLANOFTAG(tag);

	sc = trunk->sc;
	if (sc == NULL || !UP_AND_RUNNING(sc->bng_ifp)) {
		BNG_RUNLOCK(et);
		if_inc_counter(ifp, IFCOUNTER_NOPROTO, 1);
		m_freem(m);
		return;
	}

	m->m_pkthdr.rcvif = sc->bng_ifp;
	if_inc_counter(sc->bng_ifp, IFCOUNTER_IPACKETS, 1);
	BNG_RUNLOCK(et);

	/* Pass it back through the parent's input routine. */
	(*sc->bng_ifp->if_input)(sc->bng_ifp, m);
}

static void
bng_link_state(struct ifnet *ifp)
{
	if (!BNG_DVLAN_HAS(ifp))
		return vlan_link_state_p_orig(ifp);
}

static void
bng_trunk_cap(struct ifnet *ifp)
{
	if (!BNG_DVLAN_HAS(ifp))
		return vlan_trunk_cap_p_orig(ifp);
}

static void
bng_lladdr_fn(void *arg, int pending __unused)
{
	struct bng_softc *sc;
	struct ifnet *ifp;

	sc = (struct bng_softc *)arg;
	ifp = sc->bng_ifp;

	CURVNET_SET(ifp->if_vnet);

	/* The bng_ifp already has the lladdr copied in. */
	if_setlladdr(ifp, IF_LLADDR(ifp), ifp->if_addrlen);

	CURVNET_RESTORE();
}

static int
bng_config(struct bng_softc *sc, struct ifnet *p)
{
	struct epoch_tracker et;
	struct ifvlantrunk *trunk;
	struct ifnet *ifp;
	int error = 0;

	/*
	 * We can handle non-ethernet hardware types as long as
	 * they handle the tagging and headers themselves.
	 */
	if (p->if_type != IFT_ETHER &&
	    p->if_type != IFT_L2VLAN &&
	    (p->if_capenable & IFCAP_VLAN_HWTAGGING) == 0)
		return EPROTONOSUPPORT;
	if ((p->if_flags & BNG_IFFLAGS) != BNG_IFFLAGS)
		return EPROTONOSUPPORT;
	if (sc->bng_trunk)
		return EBUSY;

	BNG_XLOCK();
	if (p->if_vlantrunk == NULL) {
		trunk = malloc(sizeof(struct ifvlantrunk),
		    M_BNG, M_WAITOK | M_ZERO);
		TRUNK_LOCK_INIT(trunk);
		TRUNK_WLOCK(trunk);
		BNG_DVLAN_SET(p);
		p->if_vlantrunk = trunk;
		trunk->parent = p;
		if_ref(trunk->parent);
		TRUNK_WUNLOCK(trunk);
	} else {
		trunk = p->if_vlantrunk;
	}

	trunk->sc = sc;

	sc->bng_pcp = 0;       /* Default: best effort delivery. */
	sc->bng_encaplen = ETHER_VLAN_ENCAP_LEN;
	sc->bng_mintu = ETHERMIN;
	sc->bng_pflags = 0;
	sc->bng_capenable = -1;

	/*
	 * If the parent supports the VLAN_MTU capability,
	 * i.e. can Tx/Rx larger than ETHER_MAX_LEN frames,
	 * use it.
	 */
	if (p->if_capenable & IFCAP_VLAN_MTU) {
		/*
		 * No need to fudge the MTU since the parent can
		 * handle extended frames.
		 */
		sc->bng_mtufudge = 0;
	} else {
		/*
		 * Fudge the MTU by the encapsulation size.  This
		 * makes us incompatible with strictly compliant
		 * 802.1Q implementations, but allows us to use
		 * the feature with other NetBSD implementations,
		 * which might still be useful.
		 */
		sc->bng_mtufudge = sc->bng_encaplen;
	}

	sc->bng_trunk = trunk;
	ifp = sc->bng_ifp;
	/*
	 * Initialize fields from our parent.  This duplicates some
	 * work with ether_ifattach() but allows for non-ethernet
	 * interfaces to also work.
	 */
	ifp->if_mtu = p->if_mtu - sc->bng_mtufudge;
	ifp->if_baudrate = p->if_baudrate;
	ifp->if_output = p->if_output;
	ifp->if_input = p->if_input;
	ifp->if_resolvemulti = p->if_resolvemulti;
	ifp->if_addrlen = p->if_addrlen;
	ifp->if_broadcastaddr = p->if_broadcastaddr;
	ifp->if_pcp = sc->bng_pcp;

	/*
	 * Copy only a selected subset of flags from the parent.
	 * Other flags are none of our business.
	 */
#define VLAN_COPY_FLAGS (IFF_SIMPLEX)
	ifp->if_flags &= ~VLAN_COPY_FLAGS;
	ifp->if_flags |= p->if_flags & VLAN_COPY_FLAGS;
#undef VLAN_COPY_FLAGS

	ifp->if_link_state = p->if_link_state;

	NET_EPOCH_ENTER(et);
	bng_capabilities(sc);
	NET_EPOCH_EXIT(et);

	/*
	 * Set up our interface address to reflect the underlying
	 * physical interface's.
	 */
	bcopy(IF_LLADDR(p), IF_LLADDR(ifp), p->if_addrlen);
	((struct sockaddr_dl *)ifp->if_addr->ifa_addr)->sdl_alen =
	    p->if_addrlen;

	TASK_INIT(&sc->lladdr_task, 0, bng_lladdr_fn, sc);

	/* We are ready for operation now. */
	ifp->if_drv_flags |= IFF_DRV_RUNNING;

	/* Update flags on the parent, if necessary. */
	bng_setflags(ifp, 1);

	if (error == 0)
		EVENTHANDLER_INVOKE(bng_config, p);
	BNG_XUNLOCK();

	return error;
}

static void
bng_unconfig(struct ifnet *ifp)
{
	BNG_XLOCK();
	bng_unconfig_locked(ifp, 0);
	BNG_XUNLOCK();
}

static void
bng_unconfig_locked(struct ifnet *ifp, int departing)
{
	struct ifvlantrunk *trunk;
	struct bng_softc *sc;
	struct ifnet  *parent;

	BNG_XLOCK_ASSERT();

	sc = ifp->if_softc;
	trunk = sc->bng_trunk;
	parent = NULL;

	if (trunk != NULL) {
		parent = trunk->parent;
		bng_setflags(ifp, 0); /* clear special flags on parent */

		trunk->sc = NULL;
		sc->bng_trunk = NULL;

		/*
		 * Check if we were the last.
		 */
		if (trunk->refcnt == 0) {
			parent->if_vlantrunk = NULL;
			BNG_DVLAN_CLR(parent);
			NET_EPOCH_WAIT();
			trunk_destroy(trunk);
		}
	}

	/* Disconnect from parent. */
	if (sc->bng_pflags)
		if_printf(ifp, "%s: bng_pflags unclean\n", __func__);
	ifp->if_mtu = ETHERMTU;
	ifp->if_link_state = LINK_STATE_UNKNOWN;
	ifp->if_drv_flags &= ~IFF_DRV_RUNNING;

	/*
	 * Only dispatch an event if vlan was
	 * attached, otherwise there is nothing
	 * to cleanup anyway.
	 */
	if (parent != NULL)
		EVENTHANDLER_INVOKE(bng_unconfig, parent);
}

/* Handle a reference counted flag that should be set on the parent as well */
static int
bng_setflag(struct ifnet *ifp, int flag, int status,
	     int (*func)(struct ifnet *, int))
{
	struct bng_softc *sc;
	int error;

	BNG_SXLOCK_ASSERT();

	sc = ifp->if_softc;
	status = status ? (ifp->if_flags & flag) : 0;
	/* Now "status" contains the flag value or 0 */

	/*
	 * See if recorded parent's status is different from what
	 * we want it to be.  If it is, flip it.  We record parent's
	 * status in bng_pflags so that we won't clear parent's flag
	 * we haven't set.  In fact, we don't clear or set parent's
	 * flags directly, but get or release references to them.
	 * That's why we can be sure that recorded flags still are
	 * in accord with actual parent's flags.
	 */
	if (status != (sc->bng_pflags & flag)) {
		error = (*func)(PARENT(sc), status);
		if (error)
			return error;
		sc->bng_pflags &= ~flag;
		sc->bng_pflags |= status;
	}
	return 0;
}

/*
 * Handle IFF_* flags that require certain changes on the parent:
 * if "status" is true, update parent's flags respective to our if_flags;
 * if "status" is false, forcedly clear the flags set on parent.
 */
static int
bng_setflags(struct ifnet *ifp, int status)
{
	int error, i;

	for (i = 0; bng_pflags[i].flag; i++) {
		error = bng_setflag(ifp, bng_pflags[i].flag,
				     status, bng_pflags[i].func);
		if (error)
			return error;
	}
	return 0;
}

static void
bng_capabilities(struct bng_softc *sc)
{
	struct ifnet *p;
	struct ifnet *ifp;
	struct ifnet_hw_tsomax hw_tsomax;
	int cap = 0, ena = 0, mena;
	u_long hwa = 0;

	BNG_SXLOCK_ASSERT();
	TRUNK_RLOCK_ASSERT(TRUNK(sc));
	p = PARENT(sc);
	ifp = sc->bng_ifp;

	/* Mask parent interface enabled capabilities disabled by user. */
	mena = p->if_capenable & sc->bng_capenable;

	/*
	 * If the parent interface can do checksum offloading
	 * on VLANs, then propagate its hardware-assisted
	 * checksumming flags. Also assert that checksum
	 * offloading requires hardware VLAN tagging.
	 */
	if (p->if_capabilities & IFCAP_VLAN_HWCSUM)
		cap |= p->if_capabilities & (IFCAP_HWCSUM | IFCAP_HWCSUM_IPV6);
	if (p->if_capenable & IFCAP_VLAN_HWCSUM &&
	    p->if_capenable & IFCAP_VLAN_HWTAGGING) {
		ena |= mena & (IFCAP_HWCSUM | IFCAP_HWCSUM_IPV6);
		if (ena & IFCAP_TXCSUM)
			hwa |= p->if_hwassist & (CSUM_IP | CSUM_TCP |
			    CSUM_UDP | CSUM_SCTP);
		if (ena & IFCAP_TXCSUM_IPV6)
			hwa |= p->if_hwassist & (CSUM_TCP_IPV6 |
			    CSUM_UDP_IPV6 | CSUM_SCTP_IPV6);
	}

	/*
	 * If the parent interface can do TSO on VLANs then
	 * propagate the hardware-assisted flag. TSO on VLANs
	 * does not necessarily require hardware VLAN tagging.
	 */
	memset(&hw_tsomax, 0, sizeof(hw_tsomax));
	if_hw_tsomax_common(p, &hw_tsomax);
	if_hw_tsomax_update(ifp, &hw_tsomax);
	if (p->if_capabilities & IFCAP_VLAN_HWTSO)
		cap |= p->if_capabilities & IFCAP_TSO;
	if (p->if_capenable & IFCAP_VLAN_HWTSO) {
		ena |= mena & IFCAP_TSO;
		if (ena & IFCAP_TSO)
			hwa |= p->if_hwassist & CSUM_TSO;
	}

	/*
	 * If the parent interface can do LRO and checksum offloading on
	 * VLANs, then guess it may do LRO on VLANs.  False positive here
	 * cost nothing, while false negative may lead to some confusions.
	 */
	if (p->if_capabilities & IFCAP_VLAN_HWCSUM)
		cap |= p->if_capabilities & IFCAP_LRO;
	if (p->if_capenable & IFCAP_VLAN_HWCSUM)
		ena |= p->if_capenable & IFCAP_LRO;

	/*
	 * If the parent interface can offload TCP connections over VLANs then
	 * propagate its TOE capability to the VLAN interface.
	 *
	 * All TOE drivers in the tree today can deal with VLANs.  If this
	 * changes then IFCAP_VLAN_TOE should be promoted to a full capability
	 * with its own bit.
	 */
#define	IFCAP_VLAN_TOE IFCAP_TOE
	if (p->if_capabilities & IFCAP_VLAN_TOE)
		cap |= p->if_capabilities & IFCAP_TOE;
	if (p->if_capenable & IFCAP_VLAN_TOE) {
		TOEDEV(ifp) = TOEDEV(p);
		ena |= mena & IFCAP_TOE;
	}

	/*
	 * If the parent interface supports dynamic link state, so does the
	 * VLAN interface.
	 */
	cap |= (p->if_capabilities & IFCAP_LINKSTATE);
	ena |= (mena & IFCAP_LINKSTATE);

#ifdef RATELIMIT
	/*
	 * If the parent interface supports ratelimiting, so does the
	 * VLAN interface.
	 */
	cap |= (p->if_capabilities & IFCAP_TXRTLMT);
	ena |= (mena & IFCAP_TXRTLMT);
#endif

	ifp->if_capabilities = cap;
	ifp->if_capenable = ena;
	ifp->if_hwassist = hwa;
}

static int
bng_ioctl_set(struct ifnet *ifp, struct ifreq *ifr)
{
	struct ifnet *p;
	struct bng_softc *sc;
	struct bng_req bngreq;
	int error;

	sc = ifp->if_softc;

	error = copyin(ifr_data_get_ptr(ifr), &bngreq, sizeof(bngreq));
	if (error)
		return error;

	switch (bngreq.op) {
	case BNG_OP_SETPARENT:
		p = ifunit_ref(bngreq.brp.brp_parent);
		if (p == NULL) {
			error = ENOENT;
			break;
		}
		error = bng_config(sc, p);
		if_rele(p);

		break;

	case BNG_OP_SETENTRY:
		error = bng_cache_set(bngreq.bre.bre_haddr, bngreq.bre.bre_vid,
				bngreq.bre.bre_proto, DVE_FLAG_STATIC, 1);
		break;

	case BNG_OP_DELENTRY:
		error = bng_cache_del(bngreq.bre.bre_haddr);
		break;

	case BNG_OP_DUMP:
		error = bng_cache_dump(bngreq.brc.brc_data, bngreq.brc.brc_size);
		break;

	default:
		error = ENOSYS;
		break;
	}

	return error;
}

static int
bng_ioctl_get(struct ifnet *ifp, struct ifreq *ifr)
{
	struct ifnet *p;
	struct bng_softc *sc;
	struct bng_req bngreq;
	int error;

	sc = ifp->if_softc;

	error = copyin(ifr_data_get_ptr(ifr), &bngreq, sizeof(bngreq));
	if (error)
		return error;

	switch (bngreq.op) {
	case BNG_OP_GETPARENT:
		p = PARENT(sc);
		strlcpy(bngreq.brp.brp_parent, if_name(p), IFNAMSIZ);
		error = copyout(&bngreq, ifr_data_get_ptr(ifr), sizeof(bngreq));
		break;

	default:
		error = ENOSYS;
		break;
	}

	return error;
}

static int
bng_ioctl(struct ifnet *ifp, u_long cmd, caddr_t data)
{
	struct ifnet *p;
	struct ifreq *ifr;
	struct ifaddr *ifa;
	struct bng_softc *sc;
	struct ifvlantrunk *trunk;
	int error = 0;

	ifr = (struct ifreq *)data;
	ifa = (struct ifaddr *)data;
	sc = ifp->if_softc;

	switch (cmd) {
	case SIOCSIFADDR:
		ifp->if_flags |= IFF_UP;
		if (ifa->ifa_addr->sa_family == AF_INET)
			arp_ifinit(ifp, ifa);
		break;

	case SIOCGIFADDR:
		bcopy(IF_LLADDR(ifp), &ifr->ifr_addr.sa_data[0],
		    ifp->if_addrlen);
		break;

	case SIOCGIFMEDIA:
		BNG_SLOCK();
		if (TRUNK(sc) != NULL) {
			p = PARENT(sc);
			if_ref(p);
			error = (*p->if_ioctl)(p, SIOCGIFMEDIA, data);
			if_rele(p);
			/* Limit the result to the parent's current config. */
			if (error == 0) {
				struct ifmediareq *ifmr;

				ifmr = (struct ifmediareq *)data;
				if (ifmr->ifm_count >= 1 && ifmr->ifm_ulist) {
					ifmr->ifm_count = 1;
					error = copyout(&ifmr->ifm_current,
						ifmr->ifm_ulist,
						sizeof(int));
				}
			}
		} else {
			error = EINVAL;
		}
		BNG_SUNLOCK();
		break;

	case SIOCSIFMTU:
		/*
		 * Set the interface MTU.
		 */
		BNG_SLOCK();
		trunk = TRUNK(sc);
		if (trunk != NULL) {
			TRUNK_WLOCK(trunk);
			if (ifr->ifr_mtu >
			     (PARENT(sc)->if_mtu - sc->bng_mtufudge) ||
			    ifr->ifr_mtu <
			     (sc->bng_mintu - sc->bng_mtufudge))
				error = EINVAL;
			else
				ifp->if_mtu = ifr->ifr_mtu;
			TRUNK_WUNLOCK(trunk);
		} else
			error = EINVAL;
		BNG_SUNLOCK();
		break;

	case SIOCSIFFLAGS:
		/*
		 * We should propagate selected flags to the parent,
		 * e.g., promiscuous mode.
		 */
		BNG_XLOCK();
		if (TRUNK(sc) != NULL)
			error = bng_setflags(ifp, 1);
		BNG_XUNLOCK();
		break;

	case SIOCGVLANPCP:
		if (ifp->if_vnet != ifp->if_home_vnet) {
			error = EPERM;
			break;
		}
		ifr->ifr_vlan_pcp = sc->bng_pcp;
		break;

	case SIOCSVLANPCP:
		if (ifp->if_vnet != ifp->if_home_vnet) {
			error = EPERM;
			break;
		}
		error = priv_check(curthread, PRIV_NET_SETVLANPCP);
		if (error)
			break;
		if (ifr->ifr_vlan_pcp > 7) {
			error = EINVAL;
			break;
		}
		sc->bng_pcp = ifr->ifr_vlan_pcp;
		ifp->if_pcp = sc->bng_pcp;
		/* broadcast event about PCP change */
		EVENTHANDLER_INVOKE(ifnet_event, ifp, IFNET_EVENT_PCP);
		break;

	case SIOCSIFCAP:
		BNG_SLOCK();
		sc->bng_capenable = ifr->ifr_reqcap;
		trunk = TRUNK(sc);
		if (trunk != NULL) {
			struct epoch_tracker et;

			NET_EPOCH_ENTER(et);
			bng_capabilities(sc);
			NET_EPOCH_EXIT(et);
		}
		BNG_SUNLOCK();
		break;

	case SIOCSBNGREQ:
		error = bng_ioctl_set(ifp, ifr);
		break;

	case SIOCGBNGREQ:
		error = bng_ioctl_get(ifp, ifr);
		break;

	default:
		error = EINVAL;
		break;
	}

	return error;
}

#ifdef RATELIMIT
static int
vlan_snd_tag_alloc(struct ifnet *ifp,
    union if_snd_tag_alloc_params *params,
    struct m_snd_tag **ppmt)
{
	/* get trunk device */
	ifp = vlan_trunkdev(ifp);
	if (ifp == NULL || (ifp->if_capenable & IFCAP_TXRTLMT) == 0)
		return EOPNOTSUPP;
	/* forward allocation request */
	return (ifp->if_snd_tag_alloc(ifp, params, ppmt));
}
#endif /*RATELIMIT*/

/*EoF*/
