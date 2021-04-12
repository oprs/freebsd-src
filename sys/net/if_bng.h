/* vi:set ts=8: */

#ifndef _SYS_NET_BNG_H
#define	_SYS_NET_BNG_H

#include <sys/ioccom.h>

#include <net/if.h>
#include <net/ethernet.h>

typedef enum {
	BNG_OP_DUMP = 0,
	BNG_OP_SETPARENT,
	BNG_OP_GETPARENT,
	BNG_OP_SETENTRY,
	BNG_OP_DELENTRY,
} bng_op_type;

/* cache entry */

struct bng_entry {
	int      be_expat;
	uint8_t  be_haddr[ETHER_ADDR_LEN];
	uint32_t be_proto : 16;
	uint32_t be_vid   : 12;
	uint32_t be_flags :  4;
	int      be_creat;
	int      be_updat;
};

/* cache header */

struct bng_header {
	int              bh_ticks;
	int              bh_hz;
	unsigned         bh_nelem;
	struct bng_entry bh_entry[];
};

struct bng_req_cache {
	size_t brc_size;
	void  *brc_data;
};

struct bng_req_parent {
	char brp_parent[IFNAMSIZ];
};

struct bng_req_entry {
	uint8_t  bre_haddr[ETHER_ADDR_LEN];
	uint16_t bre_vid;
	uint16_t bre_proto;
};

struct bng_req {
	bng_op_type op;
	union {
		struct bng_req_parent brp;
		struct bng_req_entry  bre;
		struct bng_req_cache  brc;
	};
};

extern void bng_hijack_vlan(void);
extern void bng_restore_vlan(void);

#define SIOCSBNGREQ SIOCSIFGENERIC
#define SIOCGBNGREQ SIOCGIFGENERIC

#endif /* _SYS_NET_BNG_H */
