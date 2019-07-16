#include <stdio.h>

#include <common/cfgparse.h>
#include <common/errors.h>
#include <common/http.h>
#include <common/initcall.h>
#include <types/global.h>
#include <proto/arg.h>
#include <proto/http_fetch.h>
#include <proto/http_htx.h>
#include <proto/log.h>
#include <proto/http_ana.h>
#include <proto/sample.h>
#include <dac.h>

static struct {
	void *atlasimgptr;
	char *jsonpath;
	char *cookiename;
	size_t cookienamelen;
	da_atlas_t atlas;
	da_evidence_id_t useragentid;
	da_severity_t loglevel;
	char separator;
	unsigned char daset:1;
} global_deviceatlas = {
	.loglevel = 0,
	.jsonpath = 0,
	.cookiename = 0,
	.cookienamelen = 0,
	.useragentid = 0,
	.daset = 0,
	.separator = '|',
};

static int da_json_file(char **args, int section_type, struct proxy *curpx,
                        struct proxy *defpx, const char *file, int line,
                        char **err)
{
	if (*(args[1]) == 0) {
		memprintf(err, "deviceatlas json file : expects a json path.\n");
		return -1;
	}
	global_deviceatlas.jsonpath = strdup(args[1]);
	return 0;
}

static int da_log_level(char **args, int section_type, struct proxy *curpx,
                        struct proxy *defpx, const char *file, int line,
                        char **err)
{
	int loglevel;
	if (*(args[1]) == 0) {
		memprintf(err, "deviceatlas log level : expects an integer argument.\n");
		return -1;
	}

	loglevel = atol(args[1]);
	if (loglevel < 0 || loglevel > 3) {
		memprintf(err, "deviceatlas log level : expects a log level between 0 and 3, %s given.\n", args[1]);
	} else {
		global_deviceatlas.loglevel = (da_severity_t)loglevel;
	}

	return 0;
}

static int da_property_separator(char **args, int section_type, struct proxy *curpx,
                                 struct proxy *defpx, const char *file, int line,
                                 char **err)
{
	if (*(args[1]) == 0) {
		memprintf(err, "deviceatlas property separator : expects a character argument.\n");
		return -1;
	}
	global_deviceatlas.separator = *args[1];
	return 0;
}

static int da_properties_cookie(char **args, int section_type, struct proxy *curpx,
                          struct proxy *defpx, const char *file, int line,
                          char **err)
{
	if (*(args[1]) == 0) {
		memprintf(err, "deviceatlas cookie name : expects a string argument.\n");
		return -1;
	} else {
		global_deviceatlas.cookiename = strdup(args[1]);
	}
	global_deviceatlas.cookienamelen = strlen(global_deviceatlas.cookiename);
	return 0;
}

static size_t da_haproxy_read(void *ctx, size_t len, char *buf)
{
	return fread(buf, 1, len, ctx);
}

static da_status_t da_haproxy_seek(void *ctx, off_t off)
{
	return fseek(ctx, off, SEEK_SET) != -1 ? DA_OK : DA_SYS;
}

static void da_haproxy_log(da_severity_t severity, da_status_t status,
	const char *fmt, va_list args)
{
	if (global_deviceatlas.loglevel && severity <= global_deviceatlas.loglevel) {
		char logbuf[256];
		vsnprintf(logbuf, sizeof(logbuf), fmt, args);
		ha_warning("deviceatlas : %s.\n", logbuf);
	}
}

#define	DA_COOKIENAME_DEFAULT		"DAPROPS"

/*
 * module init / deinit functions. Returns 0 if OK, or a combination of ERR_*.
 */
static int init_deviceatlas(void)
{
	int err_code = 0;

	if (global_deviceatlas.jsonpath != 0) {
		FILE *jsonp;
		da_property_decl_t extraprops[] = {{0, 0}};
		size_t atlasimglen;
		da_status_t status;

		jsonp = fopen(global_deviceatlas.jsonpath, "r");
		if (jsonp == 0) {
			ha_alert("deviceatlas : '%s' json file has invalid path or is not readable.\n",
				 global_deviceatlas.jsonpath);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		da_init();
		da_seterrorfunc(da_haproxy_log);
		status = da_atlas_compile(jsonp, da_haproxy_read, da_haproxy_seek,
			&global_deviceatlas.atlasimgptr, &atlasimglen);
		fclose(jsonp);
		if (status != DA_OK) {
			ha_alert("deviceatlas : '%s' json file is invalid.\n",
				 global_deviceatlas.jsonpath);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		status = da_atlas_open(&global_deviceatlas.atlas, extraprops,
			global_deviceatlas.atlasimgptr, atlasimglen);

		if (status != DA_OK) {
			ha_alert("deviceatlas : data could not be compiled.\n");
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (global_deviceatlas.cookiename == 0) {
			global_deviceatlas.cookiename = strdup(DA_COOKIENAME_DEFAULT);
			global_deviceatlas.cookienamelen = strlen(global_deviceatlas.cookiename);
		}

		global_deviceatlas.useragentid = da_atlas_header_evidence_id(&global_deviceatlas.atlas,
			"user-agent");
		global_deviceatlas.daset = 1;

		fprintf(stdout, "Deviceatlas module loaded.\n");
	}

out:
	return err_code;
}

static void deinit_deviceatlas(void)
{
	if (global_deviceatlas.jsonpath != 0) {
		free(global_deviceatlas.jsonpath);
	}

	if (global_deviceatlas.daset == 1) {
		free(global_deviceatlas.cookiename);
		da_atlas_close(&global_deviceatlas.atlas);
		free(global_deviceatlas.atlasimgptr);
	}

	da_fini();
}

static int da_haproxy(const struct arg *args, struct sample *smp, da_deviceinfo_t *devinfo)
{
	struct buffer *tmp;
	da_propid_t prop, *pprop;
	da_status_t status;
	da_type_t proptype;
	const char *propname;
	int i;

	tmp = get_trash_chunk();
	chunk_reset(tmp);

	propname = (const char *) args[0].data.str.area;
	i = 0;

	for (; propname != 0; i ++,
	     propname = (const char *) args[i].data.str.area) {
		status = da_atlas_getpropid(&global_deviceatlas.atlas,
			propname, &prop);
		if (status != DA_OK) {
			chunk_appendf(tmp, "%c", global_deviceatlas.separator);
			continue;
		}
		pprop = &prop;
		da_atlas_getproptype(&global_deviceatlas.atlas, *pprop, &proptype);

		switch (proptype) {
			case DA_TYPE_BOOLEAN: {
				bool val;
				status = da_getpropboolean(devinfo, *pprop, &val);
				if (status == DA_OK) {
					chunk_appendf(tmp, "%d", val);
				}
				break;
			}
			case DA_TYPE_INTEGER:
			case DA_TYPE_NUMBER: {
				long val;
				status = da_getpropinteger(devinfo, *pprop, &val);
				if (status == DA_OK) {
					chunk_appendf(tmp, "%ld", val);
				}
				break;
			}
			case DA_TYPE_STRING: {
				const char *val;
				status = da_getpropstring(devinfo, *pprop, &val);
				if (status == DA_OK) {
					chunk_appendf(tmp, "%s", val);
				}
				break;
		        }
		    default:
			break;
		}

		chunk_appendf(tmp, "%c", global_deviceatlas.separator);
	}

	da_close(devinfo);

	if (tmp->data) {
		--tmp->data;
		tmp->area[tmp->data] = 0;
	}

	smp->data.u.str.area = tmp->area;
	smp->data.u.str.data = tmp->data;
	smp->data.type = SMP_T_STR;

	return 1;
}

static int da_haproxy_conv(const struct arg *args, struct sample *smp, void *private)
{
	da_deviceinfo_t devinfo;
	da_status_t status;
	const char *useragent;
	char useragentbuf[1024] = { 0 };
	int i;

	if (global_deviceatlas.daset == 0 || smp->data.u.str.data == 0) {
		return 1;
	}

	i = smp->data.u.str.data > sizeof(useragentbuf) ? sizeof(useragentbuf) : smp->data.u.str.data;
	memcpy(useragentbuf, smp->data.u.str.area, i - 1);
	useragentbuf[i - 1] = 0;

	useragent = (const char *)useragentbuf;

	status = da_search(&global_deviceatlas.atlas, &devinfo,
		global_deviceatlas.useragentid, useragent, 0);

	return status != DA_OK ? 0 : da_haproxy(args, smp, &devinfo);
}

#define DA_MAX_HEADERS       24

static int da_haproxy_fetch(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	da_evidence_t ev[DA_MAX_HEADERS];
	da_deviceinfo_t devinfo;
	da_status_t status;
	struct channel *chn;
	struct htx *htx;
	struct htx_blk *blk;
	char vbuf[DA_MAX_HEADERS][1024] = {{ 0 }};
	int i, nbh = 0;

	if (global_deviceatlas.daset == 0) {
		return 0;
	}

	chn = (smp->strm ? &smp->strm->req : NULL);
	htx = smp_prefetch_htx(smp, chn, 1);
	if (!htx)
		return 0;

	i = 0;
	for (blk = htx_get_first_blk(htx); nbh < DA_MAX_HEADERS && blk; blk = htx_get_next_blk(htx, blk)) {
		size_t vlen;
		char *pval;
		da_evidence_id_t evid;
		enum htx_blk_type type;
		struct ist n, v;
		char hbuf[24] = { 0 };
		char tval[1024] = { 0 };

		type = htx_get_blk_type(blk);

		if (type == HTX_BLK_HDR) {
			n = htx_get_blk_name(htx, blk);
			v = htx_get_blk_value(htx, blk);
		} else if (type == HTX_BLK_EOH) {
			break;
		} else {
			continue;
		}

		/* The HTTP headers used by the DeviceAtlas API are not longer */
		if (n.len >= sizeof(hbuf)) {
			continue;
		}

		memcpy(hbuf, n.ptr, n.len);
		hbuf[n.len] = 0;
		pval = v.ptr;
		vlen = v.len;
		evid = -1;
		i = v.len > sizeof(tval) - 1 ? sizeof(tval) - 1 : v.len;
		memcpy(tval, v.ptr, i);
		tval[i] = 0;
		pval = tval;

		if (strcasecmp(hbuf, "Accept-Language") == 0) {
			evid = da_atlas_accept_language_evidence_id(&global_deviceatlas.atlas);
		} else if (strcasecmp(hbuf, "Cookie") == 0) {
			char *p, *eval;
			size_t pl;

			eval = pval + vlen;
			/**
			 * The cookie value, if it exists, is located between the current header's
			 * value position and the next one
			 */
			if (http_extract_cookie_value(pval, eval, global_deviceatlas.cookiename,
						      global_deviceatlas.cookienamelen, 1, &p, &pl) == NULL) {
				continue;
			}

			vlen -= global_deviceatlas.cookienamelen - 1;
			pval = p;
			evid = da_atlas_clientprop_evidence_id(&global_deviceatlas.atlas);
		} else {
			evid = da_atlas_header_evidence_id(&global_deviceatlas.atlas, hbuf);
		}

		if (evid == -1) {
			continue;
		}

		i = vlen > sizeof(vbuf[nbh]) - 1 ? sizeof(vbuf[nbh]) - 1 : vlen;
		memcpy(vbuf[nbh], pval, i);
		vbuf[nbh][i] = 0;
		ev[nbh].key = evid;
		ev[nbh].value = vbuf[nbh];
		++ nbh;
	}

	status = da_searchv(&global_deviceatlas.atlas, &devinfo,
			ev, nbh);

	return status != DA_OK ? 0 : da_haproxy(args, smp, &devinfo);
}

static struct cfg_kw_list dacfg_kws = {{ }, {
	{ CFG_GLOBAL, "deviceatlas-json-file",	  da_json_file },
		{ CFG_GLOBAL, "deviceatlas-log-level",	  da_log_level },
		{ CFG_GLOBAL, "deviceatlas-property-separator", da_property_separator },
		{ CFG_GLOBAL, "deviceatlas-properties-cookie", da_properties_cookie },
		{ 0, NULL, NULL },
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &dacfg_kws);

/* Note: must not be declared <const> as its list will be overwritten */
static struct sample_fetch_kw_list fetch_kws = {ILH, {
	{ "da-csv-fetch", da_haproxy_fetch, ARG12(1,STR,STR,STR,STR,STR,STR,STR,STR,STR,STR,STR,STR), NULL, SMP_T_STR, SMP_USE_HRQHV },
		{ NULL, NULL, 0, 0, 0 },
}};

INITCALL1(STG_REGISTER, sample_register_fetches, &fetch_kws);

/* Note: must not be declared <const> as its list will be overwritten */
static struct sample_conv_kw_list conv_kws = {ILH, {
	{ "da-csv-conv", da_haproxy_conv, ARG12(1,STR,STR,STR,STR,STR,STR,STR,STR,STR,STR,STR,STR), NULL, SMP_T_STR, SMP_T_STR },
		{ NULL, NULL, 0, 0, 0 },
}};

static void da_haproxy_register_build_options()
{
	char *ptr = NULL;

#ifdef MOBI_DA_DUMMY_LIBRARY
	memprintf(&ptr, "Built with DeviceAtlas support (dummy library only).");
#else
	memprintf(&ptr, "Built with DeviceAtlas support (library version %u.%u).", MOBI_DA_MAJOR, MOBI_DA_MINOR);
#endif
	hap_register_build_opts(ptr, 1);
}

INITCALL1(STG_REGISTER, sample_register_convs, &conv_kws);

REGISTER_POST_CHECK(init_deviceatlas);
REGISTER_POST_DEINIT(deinit_deviceatlas);
INITCALL0(STG_REGISTER, da_haproxy_register_build_options);
