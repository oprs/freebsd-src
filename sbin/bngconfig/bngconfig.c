/* vi:set ts=8: */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <err.h>

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <net/if_bng.h>

#define DEF_CMD(name, narg, func) { name, func, narg }

typedef int (cmd_func)(int, char* const*);

struct bng_cmd {
	const char *name;
	cmd_func   *func;
	int         narg;
};

typedef enum {
	FMT_TEXT,
	FMT_JSON,
} bng_dump_fmt;

static cmd_func bng_ifnet_create;
static cmd_func bng_ifnet_destroy;
static cmd_func bng_ifnet_set_parent;
static cmd_func bng_ifnet_get_parent;
static cmd_func bng_cache_set;
static cmd_func bng_cache_del;
static cmd_func bng_cache_show;
static cmd_func bng_cache_json;

static int  bng_cache_dump      (bng_dump_fmt, int, char* const*);
static void bng_entry_dump_txt  (struct bng_header *, struct bng_entry *);
static void bng_entry_dump_json (struct bng_header *, struct bng_entry *);

static struct bng_cmd bng_cmds[] = {
	DEF_CMD("create",  1, bng_ifnet_create),
	DEF_CMD("destroy", 1, bng_ifnet_destroy),
	DEF_CMD("parent",  2, bng_ifnet_set_parent),
	DEF_CMD("parent",  1, bng_ifnet_get_parent),
	DEF_CMD("set",     3, bng_cache_set),
	DEF_CMD("del",     2, bng_cache_del),
	DEF_CMD("show",    1, bng_cache_show),
	DEF_CMD("json",    1, bng_cache_json)
};

static struct ifreq ifr;
static const char *ifname;
static int sd;

static void
usage()
{
	(void)fprintf(
		stderr,
		"usage: bngconfig <ifname> <command> [<args> ...]\n\n"
		"available commands:\n"
		"\tcreate                  create BNG interface <ifname>\n"
		"\tdestroy                 destroy <ifname>\n"
		"\tparent                  show the interface <ifname> is bound to\n"
		"\tparent <parent>         bind <ifname> to <parent>\n"
		"\tset <etheraddr> <VID>   bind address <etheraddr> to vlan #<VID>\n"
		"\tdel <etheraddr>         remove address <etheraddr> from the BNG cache\n"
		"\tshow                    list active BNG cache entries (text)\n"
		"\tjson                    list active BNG cache entries (json)\n"
	);
}

static const struct bng_cmd*
cmd_parse(int argc, char* const* argv, const struct bng_cmd *cmds, int n)
{
	int i;
	const struct bng_cmd *cmd;

	for (i = 0; i < n; ++i) {
		cmd = &cmds[i];
		if ((strcmp(argv[0], cmd->name) == 0)
		 && (argc >= cmd->narg))
			return cmd;
	}

	return NULL;
}

static int
cmd_parse_haddr(uint8_t *haddr, const char *str)
{
	int n;

	n = sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx%*c",
		&haddr[0], &haddr[1], &haddr[2],
		&haddr[3], &haddr[4], &haddr[5]);

	return (n == 6);
}

static int
bng_ifnet_create(int argc, char* const* argv)
{
	int error;

	(void)argc;
	(void)argv;

	error = ioctl(sd, SIOCIFCREATE2, &ifr);
	if ((error == 0) &&
	    (strncmp(ifr.ifr_name, ifname, sizeof(ifr.ifr_name)) != 0))
		(void)printf("%s\n", ifr.ifr_name);

	return error;
}

static int
bng_ifnet_destroy(int argc, char* const* argv)
{
	(void)argc;
	(void)argv;

	return ioctl(sd, SIOCIFDESTROY, &ifr);
}

static int
bng_ifnet_set_parent(int argc, char* const* argv)
{
	struct bng_req bngreq;

	(void)argc;

	bngreq.op = BNG_OP_SETPARENT;
	(void)strlcpy(bngreq.brp.brp_parent, argv[1], IFNAMSIZ);

	ifr.ifr_data = (caddr_t)&bngreq;
	return ioctl(sd, SIOCSBNGREQ, &ifr);
}

static int
bng_ifnet_get_parent(int argc, char* const* argv)
{
	struct bng_req bngreq;
	int error;

	(void)argc;
	(void)argv;

	bngreq.op = BNG_OP_GETPARENT;

	ifr.ifr_data = (caddr_t)&bngreq;
	error = ioctl(sd, SIOCGBNGREQ, &ifr);
	if (error == 0)
		(void)printf("%s\n", bngreq.brp.brp_parent);

	return error;
}

static int
bng_cache_set(int argc, char* const* argv)
{
	struct bng_req bngreq;
	long vid;

	(void)argc;

	if (!cmd_parse_haddr(bngreq.bre.bre_haddr, argv[1]))
		return EINVAL;

	vid = strtol(argv[2], NULL, 10);
	if ((vid < 1) || (vid > 4095))
		return EINVAL;

	bngreq.op            = BNG_OP_SETENTRY;
	bngreq.bre.bre_vid   = vid;
	bngreq.bre.bre_proto = ETHERTYPE_VLAN;

	ifr.ifr_data = (caddr_t)&bngreq;
	return ioctl(sd, SIOCSBNGREQ, &ifr);
}

static int
bng_cache_del(int argc, char* const* argv)
{
	struct bng_req bngreq;

	(void)argc;

	if (!cmd_parse_haddr(bngreq.bre.bre_haddr, argv[1]))
		return EINVAL;

	bngreq.op = BNG_OP_DELENTRY;

	ifr.ifr_data = (caddr_t)&bngreq;
	return ioctl(sd, SIOCSBNGREQ, &ifr);
}

static void
bng_entry_dump_txt(struct bng_header *bh, struct bng_entry *be)
{
	int dt;

	uint8_t *a = be->be_haddr;
	(void)printf("%02x:%02x:%02x:%02x:%02x:%02x",
		a[0], a[1], a[2], a[3], a[4], a[5]);
	(void)printf(" %4d", be->be_vid);
#if 0
	(void)printf(" %d", (bh->bh_ticks - be->be_creat) / bh->bh_hz);
	(void)printf(" %d", (bh->bh_ticks - be->be_updat) / bh->bh_hz);
#endif
	if (be->be_flags != 0) {
		(void)printf(" static\n");
	} else {
		dt = (be->be_expat - bh->bh_ticks) / bh->bh_hz;
		if (dt > 0) {
			(void)printf(" %d\n", dt);
		} else {
			(void)printf(" expired\n");
		}
	}
}

static void
bng_entry_dump_json(struct bng_header *bh, struct bng_entry *be)
{
	int dt;

	time_t now = time(NULL);

	(void)printf("{\"haddr\": ");
	uint8_t *a = be->be_haddr;
	(void)printf("\"%02x:%02x:%02x:%02x:%02x:%02x\"",
		a[0], a[1], a[2], a[3], a[4], a[5]);
	(void)printf(", \"vid\": %d", be->be_vid);
	dt = (be->be_creat - bh->bh_ticks) / bh->bh_hz;
	(void)printf(", \"created\": %lu", now + dt);
	dt = (be->be_updat - bh->bh_ticks) / bh->bh_hz;
	(void)printf(", \"updated\": %lu", now + dt);
	(void)printf(", \"type\": ");
	if (be->be_flags != 0) {
		(void)printf("\"static\"");
		dt = -1;
	} else {
		(void)printf("\"dynamic\"");
		dt = (be->be_expat - bh->bh_ticks) / bh->bh_hz;
	}
	(void)printf(", \"ttl\": %d", dt);
	(void)printf("}");
}

static void
bng_cache_dump_txt(struct bng_header *bh)
{
	struct bng_entry  *be;
	unsigned i;

	for (i = 0 ; i < bh->bh_nelem ; i++) {
		be = &bh->bh_entry[i];
		bng_entry_dump_txt(bh, be);
	}
}

static void
bng_cache_dump_json(struct bng_header *bh)
{
	struct bng_entry  *be;
	unsigned i;

	(void)printf("{\"cache\":\n [");
	for (i = 0 ; i < bh->bh_nelem ; i++) {
		be = &bh->bh_entry[i];
		bng_entry_dump_json(bh, be);
		if (i < (bh->bh_nelem - 1))
			(void)printf(",\n  ");
	}
	(void)printf("]}\n");
}

static int
bng_cache_dump(bng_dump_fmt fmt, int argc, char* const* argv)
{
	struct bng_req bngreq;
	struct bng_header *bh;
	int error;
	void *x;

	(void)argc;
	(void)argv;

	x = malloc(16*1024*1024);
	assert(x != NULL);

	bngreq.op = BNG_OP_DUMP;
	bngreq.brc.brc_size = 16*1024*1024;
	bngreq.brc.brc_data = x;

	ifr.ifr_data = (caddr_t)&bngreq;
	error = ioctl(sd, SIOCSBNGREQ, &ifr);
	if (error != 0) {
		free(x);
		return error;
	}

	bh = (struct bng_header*)x;

	switch (fmt) {
	case FMT_TEXT:
		bng_cache_dump_txt(bh);
		break;

	case FMT_JSON:
	default:
		bng_cache_dump_json(bh);
		break;
	}

	free(x);
	return 0;
}

static int
bng_cache_show(int argc, char* const* argv)
{
	return bng_cache_dump(FMT_TEXT, argc, argv);
}

static int
bng_cache_json(int argc, char* const* argv)
{
	return bng_cache_dump(FMT_JSON, argc, argv);
}

int
main(int argc, char *argv[])
{
	const struct bng_cmd *cmd;
	int error = 0;

	if (argc < 3) {
		usage();
		exit(1);
	}

	ifname = argv[1];
	if ((strncmp(ifname, "bng", 3) != 0) ||
	    ((ifname[3] != '\0') &&
	     ((ifname[3] < '0') || (ifname[3] > '9')))) {
		errno = EINVAL;
		perror(ifname);
		exit(1);
	}

	bzero(&ifr, sizeof(ifr));
	(void)strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	argv += 2;
	argc -= 2;

	sd = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (sd < 0) {
		perror(ifname);
		exit(1);
	}

	while (argc > 0 ) {
		cmd = cmd_parse(argc, argv, bng_cmds, nitems(bng_cmds));

		if (cmd == NULL) {
			usage();
			exit(1);
		}

		error = cmd->func(argc, argv);
		if (error != 0) {
			perror(ifname);
			break;
		}

		argv += cmd->narg;
		argc -= cmd->narg;
	}

	(void)close(sd);

	return error;
}

/*EoF*/
