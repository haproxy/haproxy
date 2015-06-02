#include <stdio.h>

#include <common/cfgparse.h>
#include <proto/arg.h>
#include <proto/log.h>
#include <proto/sample.h>
#include <import/da.h>

static int da_json_file(char **args, int section_type, struct proxy *curpx,
                        struct proxy *defpx, const char *file, int line,
                        char **err)
{
	if (*(args[1]) == 0) {
		memprintf(err, "deviceatlas json file : expects a json path.\n");
		return -1;
	}
	global.deviceatlas.jsonpath = strdup(args[1]);
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
		global.deviceatlas.loglevel = (da_severity_t)loglevel;
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
	global.deviceatlas.separator = *args[1];
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
	if (global.deviceatlas.loglevel && severity <= global.deviceatlas.loglevel) {
		char logbuf[256];
		vsnprintf(logbuf, sizeof(logbuf), fmt, args);
		Warning("deviceatlas : %s.\n", logbuf);
	}
}

int init_deviceatlas(void)
{
	da_status_t status = DA_SYS;
	if (global.deviceatlas.jsonpath != 0) {
		FILE *jsonp;
		da_property_decl_t extraprops[] = {{0, 0}};
		size_t atlasimglen;
		da_status_t status;

		jsonp = fopen(global.deviceatlas.jsonpath, "r");
		if (jsonp == 0) {
			Alert("deviceatlas : '%s' json file has invalid path or is not readable.\n",
				global.deviceatlas.jsonpath);
			goto out;
		}

		da_init();
		da_seterrorfunc(da_haproxy_log);
		status = da_atlas_compile(jsonp, da_haproxy_read, da_haproxy_seek,
			&global.deviceatlas.atlasimgptr, &atlasimglen);
		fclose(jsonp);
		if (status != DA_OK) {
			Alert("deviceatlas : '%s' json file is invalid.\n",
				global.deviceatlas.jsonpath);
			goto out;
		}

		status = da_atlas_open(&global.deviceatlas.atlas, extraprops,
			global.deviceatlas.atlasimgptr, atlasimglen);

		if (status != DA_OK) {
			Alert("deviceatlas : data could not be compiled.\n");
			goto out;
		}

		global.deviceatlas.useragentid = da_atlas_header_evidence_id(&global.deviceatlas.atlas,
			"user-agent");

		fprintf(stdout, "Deviceatlas module loaded.\n");
	}

out:
	return status == DA_OK;
}

void deinit_deviceatlas(void)
{
	if (global.deviceatlas.jsonpath != 0) {
		free(global.deviceatlas.jsonpath);
	}

	if (global.deviceatlas.useragentid > 0) {
		da_atlas_close(&global.deviceatlas.atlas);
		free(global.deviceatlas.atlasimgptr);
	}

	da_fini();
}

static int da_haproxy(const struct arg *args, struct sample *smp, void *private)
{
	struct chunk *tmp;
	da_deviceinfo_t devinfo;
	da_propid_t prop, *pprop;
	da_type_t proptype;
	da_status_t status;
	const char *useragent, *propname;
	char useragentbuf[1024];
	int i;

	if (global.deviceatlas.useragentid == 0) {
		return 1;
	}

	tmp = get_trash_chunk();
	chunk_reset(tmp);

	i = smp->data.str.len > sizeof(useragentbuf) ? sizeof(useragentbuf) : smp->data.str.len;
	memcpy(useragentbuf, smp->data.str.str, i - 1);
	useragentbuf[i - 1] = 0;

	useragent = (const char *)useragentbuf;
	propname = (const char *)args[0].data.str.str;
	i = 0;

	status = da_search(&global.deviceatlas.atlas, &devinfo,
		global.deviceatlas.useragentid, useragent, 0);
	if (status != DA_OK) {
		return 0;
	}

	for (; propname != 0; i ++, propname = (const char *)args[i].data.str.str) {
		status = da_atlas_getpropid(&global.deviceatlas.atlas,
			propname, &prop);
		if (status != DA_OK) {
			chunk_appendf(tmp, "%c", global.deviceatlas.separator);
			continue;
		}
		pprop = &prop;
		da_atlas_getproptype(&global.deviceatlas.atlas, *pprop, &proptype);

		switch (proptype) {
			case DA_TYPE_BOOLEAN: {
				bool val;
				status = da_getpropboolean(&devinfo, *pprop, &val);
				if (status == DA_OK) {
					chunk_appendf(tmp, "%d", val);
				}
				break;
			}
			case DA_TYPE_INTEGER:
			case DA_TYPE_NUMBER: {
				long val;
				status = da_getpropinteger(&devinfo, *pprop, &val);
				if (status == DA_OK) {
					chunk_appendf(tmp, "%ld", val);
				}
				break;
			}
			case DA_TYPE_STRING: {
				const char *val;
				status = da_getpropstring(&devinfo, *pprop, &val);
				if (status == DA_OK) {
					chunk_appendf(tmp, "%s", val);
				}
				break;
			}
		    default:
			break;
		}

		chunk_appendf(tmp, "%c", global.deviceatlas.separator);
	}

	da_close(&devinfo);

	if (tmp->len) {
		--tmp->len;
		tmp->str[tmp->len] = 0;
	}

	smp->data.str.str = tmp->str;
	smp->data.str.len = strlen(tmp->str);

	return 1;
}

static struct cfg_kw_list dacfg_kws = {{ }, {
	{ CFG_GLOBAL, "deviceatlas-json-file",	  da_json_file },
	{ CFG_GLOBAL, "deviceatlas-log-level",	  da_log_level },
	{ CFG_GLOBAL, "deviceatlas-property-separator", da_property_separator },
	{ 0, NULL, NULL },
}};

/* Note: must not be declared <const> as its list will be overwritten */
static struct sample_conv_kw_list conv_kws = {ILH, {
	{ "da-csv", da_haproxy, ARG5(1,STR,STR,STR,STR,STR), NULL, SMP_T_STR, SMP_T_STR },
	{ NULL, NULL, 0, 0, 0 },
}};

__attribute__((constructor))
static void __da_init(void)
{
	/* register sample fetch and format conversion keywords */
	sample_register_convs(&conv_kws);
	cfg_register_keywords(&dacfg_kws);
}
