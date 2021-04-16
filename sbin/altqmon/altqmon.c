/*	$OpenBSD: pfctl_qstats.c,v 1.30 2004/04/27 21:47:32 kjc Exp $ */

/*
 * Copyright (c) Henning Brauer <henning@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");
#define PFIOC_USE_LATEST

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <net/if.h>
#include <netinet/in.h>
#include <net/pfvar.h>
#include <arpa/inet.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <fcntl.h>

#include <net/altq/altq.h>
#include <net/altq/altq_cbq.h>
#include <net/altq/altq_codel.h>
#include <net/altq/altq_priq.h>
#include <net/altq/altq_hfsc.h>
#include <net/altq/altq_fairq.h>

//#include "pfctl.h"
#include "../pfctl/pfctl_parser.h"

union class_stats {
	class_stats_t		cbq_stats;
	struct priq_classstats	priq_stats;
	struct hfsc_classstats	hfsc_stats;
	struct fairq_classstats fairq_stats;
	struct codel_ifstats	codel_stats;
};

#define AVGN_MAX	8
#define STAT_INTERVAL	5

struct queue_stats {
	union class_stats	 data;
	int			 avgn;
	double			 avg_bytes;
	double			 avg_packets;
	u_int64_t		 prev_bytes;
	u_int64_t		 prev_packets;
};

struct pf_altq_node {
	struct pf_altq		 altq;
	struct pf_altq_node	*next;
	struct pf_altq_node	*children;
	struct queue_stats	 qstats;
};

void     usage(void);
int			 pfctl_update_qstats(int, struct pf_altq_node **,int opts);
void			 pfctl_insert_altq_node(struct pf_altq_node **,
			    const struct pf_altq, const struct queue_stats);
struct pf_altq_node	*pfctl_find_altq_node(struct pf_altq_node *,
			    const char *, const char *);
void			 pfctl_print_altq_node(int, const struct pf_altq_node *,
			    unsigned, int);
void			 print_cbqstats(struct queue_stats);
void			 print_codelstats(struct queue_stats);
void			 print_priqstats(struct queue_stats);
void			 print_hfscstats(struct queue_stats);
void			 print_fairqstats(struct queue_stats);
void			 pfctl_free_altq_node(struct pf_altq_node *);
void			 pfctl_print_altq_nodestat(int,
			    const struct pf_altq_node *);

void			 update_avg(struct pf_altq_node *);

int json = 0;  /* A glboal variable to signal that JSON is to be output. */

void
usage(void)
{
        extern char *__progname;

        fprintf(stderr,
		"usage: %s [-jvv]\n",
		__progname);

        exit(1);
}


int
main(int argc, char *argv[])
//pfctl_show_altq(int dev, const char *iface, int opts, int verbose2)
{
  int dev;
  char *iface=NULL;
  int opts = 0;
  int verbose2=0;
  char ch;
  int altqsupport = 1;
  while ((ch = getopt(argc, argv, "jv")) != -1) {
	switch (ch) {
	  /*case 'c':
	  opts|=PF_OPT_CLRALTQ;
	  break;*/
	case 'j':
	  json=1;
	  break;
	case 'v':
	  if (opts & PF_OPT_VERBOSE) {
	    opts |= PF_OPT_VERBOSE2;
	    verbose2=1;
	  }
	  opts |= PF_OPT_VERBOSE;
	  break;
	default:
	  usage();
	}
  }
  if (json && verbose2) {
    printf("JSON mode not valid with vv mode\n");
    json=0;
  }


	struct pf_altq_node	*root = NULL, *node;
	int			 nodes; //, dotitle = (opts & PF_OPT_SHOWALL);

	dev = open("/dev/pf", O_RDONLY);
        if (dev < 0) {
                perror("/dev/pf");
                return -1;
        }
#ifdef __FreeBSD__
        if (!altqsupport)
                return (-1);
#endif
        if ((nodes = pfctl_update_qstats(dev, &root,opts)) < 0)
                return (-1);
	
	if (nodes == 0) {
	  if (!json) {
		printf("No queue in use\n");
	  } else {
		printf("{No queue in use}\n");
	  }
	}
	if (json)
	  printf("{\"qstats\":[");
	for (node = root; node != NULL; node = node->next) {
		if (iface != NULL && strcmp(node->altq.ifname, iface))
			continue;
		if (json) {
		  printf("{");
		}
		pfctl_print_altq_node(dev, node, 0, opts);
		if (json) {
		  printf("}");
		  if (node->next != NULL)
		    printf(",\n");
		}
	}
	if (json)
	  printf("]}\n");

	while (verbose2 && nodes > 0) {
		printf("\n");
		fflush(stdout);
		sleep(STAT_INTERVAL);
		if ((nodes = pfctl_update_qstats(dev, &root,opts)) == -1)
			return (-1);
		for (node = root; node != NULL; node = node->next) {
			if (iface != NULL && strcmp(node->altq.ifname, iface))
				continue;
#ifdef __FreeBSD__
			if (node->altq.local_flags & PFALTQ_FLAG_IF_REMOVED)
				continue;
#endif
			pfctl_print_altq_node(dev, node, 0, opts);

		}
	}
	pfctl_free_altq_node(root);

	return (0);
}

int
pfctl_update_qstats(int dev, struct pf_altq_node **root, int opts)
{
	struct pf_altq_node	*node;
	struct pfioc_altq	 pa;
	struct pfioc_qstats	 pq;
	u_int32_t		 mnr, nr;
	struct queue_stats	 qstats;
	static	u_int32_t	 last_ticket;

	memset(&pa, 0, sizeof(pa));
	memset(&pq, 0, sizeof(pq));
	memset(&qstats, 0, sizeof(qstats));

	pa.version = PFIOC_ALTQ_VERSION;
	if (ioctl(dev, DIOCGETALTQS, &pa)) {
		warn("DIOCGETALTQS");
		return (-1);
	}

	/* if a new set is found, start over */
	if (pa.ticket != last_ticket && *root != NULL) {
		pfctl_free_altq_node(*root);
		*root = NULL;
	}
	last_ticket = pa.ticket;

	mnr = pa.nr;
	for (nr = 0; nr < mnr; ++nr) {
	  
		pa.nr = nr;
		if (ioctl(dev, DIOCGETALTQ, &pa)) {
			warn("DIOCGETALTQ");
			return (-1);
		}
#ifdef __FreeBSD__
		if ((pa.altq.qid > 0 || pa.altq.scheduler == ALTQT_CODEL) &&
		    !(pa.altq.local_flags & PFALTQ_FLAG_IF_REMOVED)) {
#else
		if (pa.altq.qid > 0) {
#endif
			pq.nr = nr;
			pq.ticket = pa.ticket;
			pq.buf = &qstats.data;
			pq.nbytes = sizeof(qstats.data);
			pq.version = altq_stats_version(pa.altq.scheduler);
			// Set clear flag
			//if (opts & PF_OPT_CLRALTQ) {
			  //printf("Skon - setting clear bit\n");
			//  pq.clear = 1;
			//}
			if (ioctl(dev, DIOCGETQSTATS, &pq)) {
				warn("DIOCGETQSTATS");
				printf("In pfctl_update_qstats error\n");
				
				return (-1);
			}
			if ((node = pfctl_find_altq_node(*root, pa.altq.qname,
			    pa.altq.ifname)) != NULL) {
				memcpy(&node->qstats.data, &qstats.data,
				    sizeof(qstats.data));
				update_avg(node);
			} else {
				pfctl_insert_altq_node(root, pa.altq, qstats);
			}
		}
#ifdef __FreeBSD__
		else if (pa.altq.local_flags & PFALTQ_FLAG_IF_REMOVED) {
			memset(&qstats.data, 0, sizeof(qstats.data));
			if ((node = pfctl_find_altq_node(*root, pa.altq.qname,
			    pa.altq.ifname)) != NULL) {
				memcpy(&node->qstats.data, &qstats.data,
				    sizeof(qstats.data));
				update_avg(node);
			} else {
				pfctl_insert_altq_node(root, pa.altq, qstats);
			}
		}
#endif
	}
	return (mnr);
}

void
pfctl_insert_altq_node(struct pf_altq_node **root,
    const struct pf_altq altq, const struct queue_stats qstats)
{
	struct pf_altq_node	*node;

	node = calloc(1, sizeof(struct pf_altq_node));
	if (node == NULL)
		err(1, "pfctl_insert_altq_node: calloc");
	memcpy(&node->altq, &altq, sizeof(struct pf_altq));
	memcpy(&node->qstats, &qstats, sizeof(qstats));
	node->next = node->children = NULL;

	if (*root == NULL)
		*root = node;
	else if (!altq.parent[0]) {
		struct pf_altq_node	*prev = *root;

		while (prev->next != NULL)
			prev = prev->next;
		prev->next = node;
	} else {
		struct pf_altq_node	*parent;

		parent = pfctl_find_altq_node(*root, altq.parent, altq.ifname);
		if (parent == NULL)
			errx(1, "parent %s not found", altq.parent);
		if (parent->children == NULL)
			parent->children = node;
		else {
			struct pf_altq_node *prev = parent->children;

			while (prev->next != NULL)
				prev = prev->next;
			prev->next = node;
		}
	}
	update_avg(node);
}
/*                                                                                                   
 * misc utilities                                                                                    
 */
#define R2S_BUFS        8
#define RATESTR_MAX     16

static char *
rate2str(double rate)
{
	char            *buf;
        static char      r2sbuf[R2S_BUFS][RATESTR_MAX];  /* ring bufer */
	static int       idx = 0;
        int              i;
	static const char unit[] = " KMG";

        buf = r2sbuf[idx++];
        if (idx == R2S_BUFS)
                idx = 0;

 	for (i = 0; rate >= 1000 && i <= 3; i++)
	        rate /= 1000;

        if ((int)(rate * 100) % 100)
	        snprintf(buf, RATESTR_MAX, "%.2f%cb", rate, unit[i]);
        else
		snprintf(buf, RATESTR_MAX, "%d%cb", (int)rate, unit[i]);

	return (buf);
}


 
static void
print_hfsc_sc(const char *scname, u_int m1, u_int d, u_int m2,
    const struct node_hfsc_sc *sc)
{
        printf(" %s", scname);

        if (d != 0) {
                printf("(");
                if (sc != NULL && sc->m1.bw_percent > 0)
                        printf("%u%%", sc->m1.bw_percent);
                else
                    	printf("%s", rate2str((double)m1));
                printf(" %u", d);
        }

        if (sc != NULL && sc->m2.bw_percent > 0)
		printf(" %u%%", sc->m2.bw_percent);
        else
                printf(" %s", rate2str((double)m2));

 	if (d != 0)
                printf(")");
}


struct pf_altq_node *
pfctl_find_altq_node(struct pf_altq_node *root, const char *qname,
    const char *ifname)
{
	struct pf_altq_node	*node, *child;

	for (node = root; node != NULL; node = node->next) {
		if (!strcmp(node->altq.qname, qname)
		    && !(strcmp(node->altq.ifname, ifname)))
			return (node);
		if (node->children != NULL) {
			child = pfctl_find_altq_node(node->children, qname,
			    ifname);
			if (child != NULL)
				return (child);
		}
	}
	return (NULL);
}

static int
print_hfsc_opts(const struct pf_altq *a, const struct node_queue_opt *qopts)
{
        const struct hfsc_opts_v1       *opts;
        const struct node_hfsc_sc       *rtsc, *lssc, *ulsc;

        opts = &a->pq_u.hfsc_opts;
        if (qopts == NULL)
                rtsc = lssc = ulsc = NULL;
        else {
                rtsc = &qopts->data.hfsc_opts.realtime;
                lssc = &qopts->data.hfsc_opts.linkshare;
                ulsc = &qopts->data.hfsc_opts.upperlimit;
        }

        if (opts->flags || opts->rtsc_m2 != 0 || opts->ulsc_m2 != 0 ||
            (opts->lssc_m2 != 0 && (opts->lssc_m2 != a->bandwidth ||
            opts->lssc_d != 0))) {
                printf("hfsc(");
                if (opts->flags & HFCF_RED)
                        printf(" red");
                if (opts->flags & HFCF_ECN)
                        printf(" ecn");
                if (opts->flags & HFCF_RIO)
                        printf(" rio");
                if (opts->flags & HFCF_CODEL)
                        printf(" codel");
                if (opts->flags & HFCF_CLEARDSCP)
                        printf(" cleardscp");
                if (opts->flags & HFCF_DEFAULTCLASS)
                        printf(" default");
                if (opts->rtsc_m2 != 0)
                        print_hfsc_sc("realtime", opts->rtsc_m1, opts->rtsc_d,
                            opts->rtsc_m2, rtsc);
                if (opts->lssc_m2 != 0 && (opts->lssc_m2 != a->bandwidth ||
                    opts->lssc_d != 0))
                        print_hfsc_sc("linkshare", opts->lssc_m1, opts->lssc_d,
                            opts->lssc_m2, lssc);
                if (opts->ulsc_m2 != 0)
                        print_hfsc_sc("upperlimit", opts->ulsc_m1, opts->ulsc_d,
                            opts->ulsc_m2, ulsc);
                printf(" ) ");
   
                return (1);
        } else
                return (0);
}

#define DEFAULT_QLIMIT		50
#define DEFAULT_PRIORITY	1
void
print_queue(const struct pf_altq *a, unsigned int level,
    struct node_queue_bw *bw, int print_interface,
	    struct node_queue_opt *qopts)
{
        unsigned int    i;

#ifdef __FreeBSD__
        if (a->local_flags & PFALTQ_FLAG_IF_REMOVED)
                printf("INACTIVE ");
#endif
	if (json) {
	  printf("\"name\":");
	} else {
	  printf("queue ");
	}
	if (!json) {
	  for (i = 0; i < level; ++i)
	    printf(" ");
	  printf("%s ", a->qname);
	} else {
	  printf("\"%s \"", a->qname);
        }
        if (print_interface) {
	  if(!json) {
	    printf("on %s ", a->ifname);
	  } else {
	    printf(",\"interface\":\"%s\"", a->ifname);
	  }
	}
        if (a->scheduler == ALTQT_CBQ || a->scheduler == ALTQT_HFSC ||
                a->scheduler == ALTQT_FAIRQ) {
                if (bw != NULL && bw->bw_percent > 0) {
		  if (bw->bw_percent < 100) {
		    if (!json) {
		      printf("bandwidth %u%% ", bw->bw_percent);
		    } else {
		      printf(",\"bandwidth\",\" %u%%\"", bw->bw_percent);
		    }
		  } else {
		    if (!json) {
                        printf("bandwidth %s ", rate2str((double)a->bandwidth));
		    } else {
                         printf(",\"bandwidth\":\"%s\"", rate2str((double)a->bandwidth));
		    }
		  }
		}
		if (a->priority != DEFAULT_PRIORITY) {
		  if (!json) {
		    printf("priority %u ", a->priority);
		  } else {
		    printf(",\"priority\":\"%u\"", a->priority);
		  }
		}
		if (a->qlimit != DEFAULT_QLIMIT) {
		  if (!json) {
		    printf("qlimit %u ", a->qlimit);
		  } else {
		    printf(",\"qlimit\":\"%u\"", a->qlimit);
		  }
		}
	}
        switch (a->scheduler) {
        case ALTQT_CBQ:
                break;
        case ALTQT_PRIQ:
                break;
        case ALTQT_HFSC:
   	        if (!json)
                   print_hfsc_opts(a, qopts);
                break;
        case ALTQT_FAIRQ:
                break;
        }

}

void
print_altq(const struct pf_altq *a, unsigned int level,
	   struct node_queue_bw *bw, struct node_queue_opt *qopts)
{
        if (a->qname[0] != 0) {
	  print_queue(a, level, bw, 1, qopts);
                return;
        }

#ifdef __FreeBSD__
        if (a->local_flags & PFALTQ_FLAG_IF_REMOVED)
                printf("INACTIVE ");
#endif

        switch (a->scheduler) {
        case ALTQT_CBQ:
                break;
        case ALTQT_PRIQ:
                break;
        case ALTQT_HFSC:
	  if (!print_hfsc_opts(a, qopts)) {
	    if (!json) {
	      printf("hfsc ");
	    }
	  }
                break;
        case ALTQT_FAIRQ:
                break;
        case ALTQT_CODEL:
                break;
        }

        if (bw != NULL && bw->bw_percent > 0) {
                if (bw->bw_percent < 100)
                        printf("bandwidth %u%% ", bw->bw_percent);
        } else
                printf("bandwidth %s ", rate2str((double)a->ifbandwidth));

        if (a->qlimit != DEFAULT_QLIMIT)
                printf("qlimit %u ", a->qlimit);
        printf("tbrsize %u ", a->tbrsize);
}
	

void
pfctl_print_altq_node(int dev, const struct pf_altq_node *node,
    unsigned int level, int opts)
{
	const struct pf_altq_node	*child;

	if (node == NULL)
		return;

	print_altq(&node->altq, level, NULL, NULL);
	if (node->children != NULL) {
	  if (!json) {
	    printf("{");
	  } else {
	    printf(",\"children\":[");
	  }
	  for (child = node->children; child != NULL;
	       child = child->next) {
	    if (!json) {
	      printf("%s", child->altq.qname);
	    } else {
	      printf("\"%s\"", child->altq.qname);
	      }

	    if (child->next != NULL)
	      printf(", ");
	  }
	  if (!json) {
	    printf("}");
	    printf("\n");
	  } else {
	    printf("]");
	  }
	}
	if (opts & PF_OPT_VERBOSE) {
		pfctl_print_altq_nodestat(dev, node);
	}
	for (child = node->children; child != NULL;
	     child = child->next) {
	        if (json) {
		  printf("},\n{");
		}
		pfctl_print_altq_node(dev, child, level + 1, opts);
	}
}

void
pfctl_print_altq_nodestat(int dev, const struct pf_altq_node *a)
{
	if (a->altq.qid == 0 && a->altq.scheduler != ALTQT_CODEL)
		return;

#ifdef __FreeBSD__
	if (a->altq.local_flags & PFALTQ_FLAG_IF_REMOVED)
		return;
#endif
	switch (a->altq.scheduler) {
	case ALTQT_CBQ:
		break;
	case ALTQT_PRIQ:
		break;
	case ALTQT_HFSC:
		print_hfscstats(a->qstats);
		break;
	case ALTQT_FAIRQ:
		break;
	case ALTQT_CODEL:
		break;
	}
}

void
print_cbqstats(struct queue_stats cur)
{
	printf("  [ pkts: %10llu  bytes: %10llu  "
	    "dropped pkts: %6llu bytes: %6llu ]\n",
	    (unsigned long long)cur.data.cbq_stats.xmit_cnt.packets,
	    (unsigned long long)cur.data.cbq_stats.xmit_cnt.bytes,
	    (unsigned long long)cur.data.cbq_stats.drop_cnt.packets,
	    (unsigned long long)cur.data.cbq_stats.drop_cnt.bytes);
	printf("  [ qlength: %3d/%3d  borrows: %6u  suspends: %6u ]\n",
	    cur.data.cbq_stats.qcnt, cur.data.cbq_stats.qmax,
	    cur.data.cbq_stats.borrows, cur.data.cbq_stats.delays);

	if (cur.avgn < 2)
		return;

	printf("  [ measured: %7.1f packets/s, %s/s ]\n",
	    cur.avg_packets / STAT_INTERVAL,
	    rate2str((8 * cur.avg_bytes) / STAT_INTERVAL));
}

void
print_codelstats(struct queue_stats cur)
{
	printf("  [ pkts: %10llu  bytes: %10llu  "
	    "dropped pkts: %6llu bytes: %6llu ]\n",
	    (unsigned long long)cur.data.codel_stats.cl_xmitcnt.packets,
	    (unsigned long long)cur.data.codel_stats.cl_xmitcnt.bytes,
	    (unsigned long long)cur.data.codel_stats.cl_dropcnt.packets +
	    cur.data.codel_stats.stats.drop_cnt.packets,
	    (unsigned long long)cur.data.codel_stats.cl_dropcnt.bytes +
	    cur.data.codel_stats.stats.drop_cnt.bytes);
	printf("  [ qlength: %3d/%3d ]\n",
	    cur.data.codel_stats.qlength, cur.data.codel_stats.qlimit);

	if (cur.avgn < 2)
		return;

	printf("  [ measured: %7.1f packets/s, %s/s ]\n",
	    cur.avg_packets / STAT_INTERVAL,
	    rate2str((8 * cur.avg_bytes) / STAT_INTERVAL));
}

void
print_priqstats(struct queue_stats cur)
{
	printf("  [ pkts: %10llu  bytes: %10llu  "
	    "dropped pkts: %6llu bytes: %6llu ]\n",
	    (unsigned long long)cur.data.priq_stats.xmitcnt.packets,
	    (unsigned long long)cur.data.priq_stats.xmitcnt.bytes,
	    (unsigned long long)cur.data.priq_stats.dropcnt.packets,
	    (unsigned long long)cur.data.priq_stats.dropcnt.bytes);
	printf("  [ qlength: %3d/%3d ]\n",
	    cur.data.priq_stats.qlength, cur.data.priq_stats.qlimit);

	if (cur.avgn < 2)
		return;

	printf("  [ measured: %7.1f packets/s, %s/s ]\n",
	    cur.avg_packets / STAT_INTERVAL,
	    rate2str((8 * cur.avg_bytes) / STAT_INTERVAL));
}

void
print_hfscstats(struct queue_stats cur)
{
  if (!json) {
    printf("  [ pkts: %10llu  bytes: %10llu  "
	   "dropped pkts: %6llu bytes: %6llu ]\n",
	   (unsigned long long)cur.data.hfsc_stats.xmit_cnt.packets,
	   (unsigned long long)cur.data.hfsc_stats.xmit_cnt.bytes,
	   (unsigned long long)cur.data.hfsc_stats.drop_cnt.packets,
	   (unsigned long long)cur.data.hfsc_stats.drop_cnt.bytes);
    printf("  [ qlength: %3d/%3d ]\n",
	   cur.data.hfsc_stats.qlength, cur.data.hfsc_stats.qlimit);
    
    if (cur.avgn < 2)
      return;

    printf("  [ measured: %7.1f packets/s, %s/s ]\n",
	   cur.avg_packets / STAT_INTERVAL,
	   rate2str((8 * cur.avg_bytes) / STAT_INTERVAL));
  } else {
    printf(",\"pkts\":%llu,\"bytes\":%llu,"
	   "\"droppedpkts\":%llu,\"droppedbytes\":%llu",
	   (unsigned long long)cur.data.hfsc_stats.xmit_cnt.packets,
	   (unsigned long long)cur.data.hfsc_stats.xmit_cnt.bytes,
	   (unsigned long long)cur.data.hfsc_stats.drop_cnt.packets,
	   (unsigned long long)cur.data.hfsc_stats.drop_cnt.bytes);
    printf(",\"qlength\":\"%d/%d\"",
	   cur.data.hfsc_stats.qlength, cur.data.hfsc_stats.qlimit);
    
    if (cur.avgn < 2)
      return;

    printf(",\"packet_s\":%7.1f,\"bytes_s\":\"%s\"",
	   cur.avg_packets / STAT_INTERVAL,
	   rate2str((8 * cur.avg_bytes) / STAT_INTERVAL));

  }
  
}

void
print_fairqstats(struct queue_stats cur)
{
	printf("  [ pkts: %10llu  bytes: %10llu  "
	    "dropped pkts: %6llu bytes: %6llu ]\n",
	    (unsigned long long)cur.data.fairq_stats.xmit_cnt.packets,
	    (unsigned long long)cur.data.fairq_stats.xmit_cnt.bytes,
	    (unsigned long long)cur.data.fairq_stats.drop_cnt.packets,
	    (unsigned long long)cur.data.fairq_stats.drop_cnt.bytes);
	printf("  [ qlength: %3d/%3d ]\n",
	    cur.data.fairq_stats.qlength, cur.data.fairq_stats.qlimit);

	if (cur.avgn < 2)
		return;

	printf("  [ measured: %7.1f packets/s, %s/s ]\n",
	    cur.avg_packets / STAT_INTERVAL,
	    rate2str((8 * cur.avg_bytes) / STAT_INTERVAL));
}

void
pfctl_free_altq_node(struct pf_altq_node *node)
{
	while (node != NULL) {
		struct pf_altq_node	*prev;

		if (node->children != NULL)
			pfctl_free_altq_node(node->children);
		prev = node;
		node = node->next;
		free(prev);
	}
}

void
update_avg(struct pf_altq_node *a)
{
	struct queue_stats	*qs;
	u_int64_t		 b, p;
	int			 n;

	if (a->altq.qid == 0 && a->altq.scheduler != ALTQT_CODEL)
		return;

	qs = &a->qstats;
	n = qs->avgn;

	switch (a->altq.scheduler) {
	case ALTQT_CBQ:
		b = qs->data.cbq_stats.xmit_cnt.bytes;
		p = qs->data.cbq_stats.xmit_cnt.packets;
		break;
	case ALTQT_PRIQ:
		b = qs->data.priq_stats.xmitcnt.bytes;
		p = qs->data.priq_stats.xmitcnt.packets;
		break;
	case ALTQT_HFSC:
		b = qs->data.hfsc_stats.xmit_cnt.bytes;
		p = qs->data.hfsc_stats.xmit_cnt.packets;
		break;
	case ALTQT_FAIRQ:
		b = qs->data.fairq_stats.xmit_cnt.bytes;
		p = qs->data.fairq_stats.xmit_cnt.packets;
		break;
	case ALTQT_CODEL:
		b = qs->data.codel_stats.cl_xmitcnt.bytes;
		p = qs->data.codel_stats.cl_xmitcnt.packets;
		break;
	default:
		b = 0;
		p = 0;
		break;
	}

	if (n == 0) {
		qs->prev_bytes = b;
		qs->prev_packets = p;
		qs->avgn++;
		return;
	}

	if (b >= qs->prev_bytes)
		qs->avg_bytes = ((qs->avg_bytes * (n - 1)) +
		    (b - qs->prev_bytes)) / n;

	if (p >= qs->prev_packets)
		qs->avg_packets = ((qs->avg_packets * (n - 1)) +
		    (p - qs->prev_packets)) / n;

	qs->prev_bytes = b;
	qs->prev_packets = p;
	if (n < AVGN_MAX)
		qs->avgn++;
}
