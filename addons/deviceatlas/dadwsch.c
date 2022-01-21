#define _GNU_SOURCE
#include <dac.h>
#include <dadwcurl.h>
#include <dadwarc.h>
#include <getopt.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>

#define ATLASTOKSZ PATH_MAX
#define ATLASMAPNM "/hapdeviceatlas"

const char *__pgname;

static struct {
	da_dwatlas_t o;
	int ofd;
	void* atlasmap;
} global_deviceatlassch = {
	.ofd = -1,
	.atlasmap = NULL
};


void usage(void)
{
	fprintf(stderr, "%s -u download URL [-d hour (in H:M:S format) current hour by default] [-p path for the downloaded file, /tmp by default]\n", __pgname);
	exit(EXIT_FAILURE);
}

static size_t jsonread(void *ctx, size_t count, char *buf)
{
	return fread(buf, 1, count, ctx);
}

static da_status_t jsonseek(void *ctx, off_t pos)
{
	return fseek(ctx, pos, SEEK_SET) != -1 ? DA_OK : DA_SYS;
}

static void dadwlog(dw_config_t cfg, const char* msg)
{
	time_t now = time(NULL);
	char buf[26] = {0};
	ctime_r(&now, buf);
	buf[24] = 0;
	fprintf(stderr, "%s: %s\n", buf, msg);
}

static dw_status_t dadwnot(void *a, dw_config_t *cfg)
{
	da_dwatlas_t *o = (da_dwatlas_t *)a;
	if (!o)
		return DW_ERR;
	char *e;
	char jsondbuf[26] = {0}, buf[26] = {0}, atlasp[ATLASTOKSZ] = {0};
	time_t now = time(NULL);
	time_t jsond;
	int fd = -1;
	(void)a;
	jsond = da_getdatacreation(&o->atlas);
	dwgetfinalp(o->dcfg.info, atlasp, sizeof(atlasp));
	ctime_r(&jsond, jsondbuf);
	ctime_r(&now, buf);
	jsondbuf[24] = 0;
	buf[24] = 0;

	printf("%s: data file generated on `%s`\n", buf, jsondbuf);
	int val = 1;
	unsigned char *ptr = (unsigned char *)global_deviceatlassch.atlasmap;
	memset(ptr, 0, sizeof(atlasp));
	strcpy(ptr, atlasp);
	return DW_OK;
}

static da_status_t dadwinit(void)
{
	if ((global_deviceatlassch.ofd = shm_open(ATLASMAPNM, O_RDWR | O_CREAT, 0660)) == -1) {
		fprintf(stderr, "%s\n", strerror(errno));
		return DA_SYS;
	}

	if (ftruncate(global_deviceatlassch.ofd, ATLASTOKSZ) == -1) {
		close(global_deviceatlassch.ofd);
		return DA_SYS;
	}
	lseek(global_deviceatlassch.ofd, 0, SEEK_SET);
	global_deviceatlassch.atlasmap = mmap(0, ATLASTOKSZ, PROT_READ | PROT_WRITE, MAP_SHARED, global_deviceatlassch.ofd, 0);
	if (global_deviceatlassch.atlasmap == MAP_FAILED) {
		fprintf(stderr, "%s\n", strerror(errno));
		return DA_SYS;
	} else {
		memset(global_deviceatlassch.atlasmap, 0, ATLASTOKSZ);
		return DA_OK;
	}
}

static void dadwexit(int sig __attribute__((unused)), siginfo_t *s __attribute__((unused)), void *ctx __attribute__((unused)))
{
	ssize_t w;

	fprintf(stderr, "%s: exit\n", __pgname);
	dw_daatlas_close(&global_deviceatlassch.o);
	da_fini();
	munmap(global_deviceatlassch.atlasmap, ATLASTOKSZ);
	close(global_deviceatlassch.ofd);
	shm_unlink(ATLASMAPNM);
	exit(EXIT_SUCCESS);
}

int main(int argc, char **argv)
{
	const char *opts = "u:p:d:h";
	bool dset = false;
	size_t i;
	int ch;

	da_property_decl_t extraprops[1] = {
		{ 0, 0 }
	};

	__pgname = argv[0];

	dw_df_dainit_fn = curldwinit;
	dw_df_dacleanup_fn = curldwcleanup;

	da_init();
	memset(&global_deviceatlassch.o.dcfg, 0, sizeof(global_deviceatlassch.o.dcfg));
	while ((ch = getopt(argc, argv, opts)) != -1) {
		switch (ch) {
		case 'u':
			global_deviceatlassch.o.dcfg.info.url = strdup(optarg);
			break;
		case 'p':
			global_deviceatlassch.o.dcfg.info.path = strdup(optarg);
			break;
		case 'd':
			if (strptime(optarg, "%H:%M:%S", &global_deviceatlassch.o.dcfg.info.rtm) != NULL)
				dset = true;
			else
				usage();
			break;
		case 'h':
		default:
			usage();
		}
	}

	if (!dset) {
		time_t now = time(NULL);
		struct tm *cnow = gmtime(&now);
		memcpy(&global_deviceatlassch.o.dcfg.info.rtm, cnow, offsetof(struct tm, tm_mday));
	}

	if (!global_deviceatlassch.o.dcfg.info.url)
		usage();

	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = SA_SIGINFO | SA_RESTART;
	sa.sa_sigaction = dadwexit;

	global_deviceatlassch.o.dcfg.info.datatm = 1;
	global_deviceatlassch.o.dcfg.info.chksum = 1;
	global_deviceatlassch.o.dcfg.info.reload = 1;
	global_deviceatlassch.o.dcfg.info.tobin = 1;
	global_deviceatlassch.o.dcfg.ep = extraprops;
	global_deviceatlassch.o.dcfg.dwproc = curldwproc;
	global_deviceatlassch.o.dcfg.dwextract = dadwextract;
	global_deviceatlassch.o.dcfg.lptr = (void *)stderr;
	global_deviceatlassch.o.dcfg.dwlog = &dadwlog;
	global_deviceatlassch.o.dcfg.dwnotify_n = &dadwnot;
	global_deviceatlassch.o.rfn = jsonread;
	global_deviceatlassch.o.posfn = jsonseek;

	if (dadwinit() != DA_OK) {
		fprintf(stderr, "%s init failed\n", __pgname);
		exit(EXIT_FAILURE);
	}

	if (da_atlas_open_schedule(&global_deviceatlassch.o) != DA_OK) {
		fprintf(stderr, "%s scheduling failed\n", __pgname);
		exit(EXIT_FAILURE);
	}

	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGQUIT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	while (true) sleep(1);

	return 0;
}
