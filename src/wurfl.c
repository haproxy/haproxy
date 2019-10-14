#include <stdio.h>
#include <stdarg.h>

#include <common/cfgparse.h>
#include <common/chunk.h>
#include <common/buffer.h>
#include <common/errors.h>
#include <common/initcall.h>
#include <types/global.h>
#include <proto/arg.h>
#include <proto/log.h>
#include <proto/http_ana.h>
#include <proto/http_fetch.h>
#include <proto/http_htx.h>
#include <proto/sample.h>
#include <ebsttree.h>
#include <ebmbtree.h>

#include <wurfl/wurfl.h>

static struct {
	char *data_file; /* the WURFL data file */
	char *cache_size; /* the WURFL cache parameters */
	struct list patch_file_list; /* the list of WURFL patch file to use */
	char information_list_separator; /* the separator used in request to separate values */
	struct list information_list; /* the list of WURFL data to return into request */
	void *handle; /* the handle to WURFL engine */
	struct eb_root btree; /* btree containing info (name/type) on WURFL data to return */
} global_wurfl = {
	.data_file = NULL,
	.cache_size = NULL,
	.information_list_separator = ',',
	.information_list = LIST_HEAD_INIT(global_wurfl.information_list),
	.patch_file_list = LIST_HEAD_INIT(global_wurfl.patch_file_list),
	.handle = NULL,
};

#ifdef WURFL_DEBUG
inline static void ha_wurfl_log(char * message, ...)
{
	char logbuf[256];
	va_list argp;

	va_start(argp, message);
	vsnprintf(logbuf, sizeof(logbuf), message, argp);
	va_end(argp);
	send_log(NULL, LOG_NOTICE, "%s", logbuf);
}
#else
inline static void ha_wurfl_log(char * message, ...)
{
}
#endif

#define HA_WURFL_MAX_HEADER_LENGTH 1024

typedef char *(*PROP_CALLBACK_FUNC)(wurfl_handle wHandle, wurfl_device_handle dHandle);

enum wurfl_data_type {
	HA_WURFL_DATA_TYPE_UNKNOWN = 0,
	HA_WURFL_DATA_TYPE_CAP = 100,
	HA_WURFL_DATA_TYPE_VCAP = 200,
	HA_WURFL_DATA_TYPE_PROPERTY = 300
};

typedef struct {
	char *name;
	enum wurfl_data_type type;
	PROP_CALLBACK_FUNC func_callback;
	struct ebmb_node nd;
} wurfl_data_t;

static const char HA_WURFL_MODULE_VERSION[] = "2.0";
static const char HA_WURFL_ISDEVROOT_FALSE[] = "FALSE";
static const char HA_WURFL_ISDEVROOT_TRUE[] = "TRUE";

static const char HA_WURFL_DATA_TYPE_UNKNOWN_STRING[] = "unknown";
static const char HA_WURFL_DATA_TYPE_CAP_STRING[] = "capability";
static const char HA_WURFL_DATA_TYPE_VCAP_STRING[] = "virtual_capability";
static const char HA_WURFL_DATA_TYPE_PROPERTY_STRING[] = "property";

static const char *ha_wurfl_retrieve_header(const char *header_name, const void *wh);
static const char *ha_wurfl_get_wurfl_root_id (wurfl_handle wHandle, wurfl_device_handle dHandle);
static const char *ha_wurfl_get_wurfl_id (wurfl_handle wHandle, wurfl_device_handle dHandle);
static const char *ha_wurfl_get_wurfl_isdevroot (wurfl_handle wHandle, wurfl_device_handle dHandle);
static const char *ha_wurfl_get_wurfl_useragent (wurfl_handle wHandle, wurfl_device_handle dHandle);
static const char *ha_wurfl_get_wurfl_api_version (wurfl_handle wHandle, wurfl_device_handle dHandle);
static const char *ha_wurfl_get_wurfl_engine_target (wurfl_handle wHandle, wurfl_device_handle dHandle);
static const char *ha_wurfl_get_wurfl_info (wurfl_handle wHandle, wurfl_device_handle dHandle);
static const char *ha_wurfl_get_wurfl_last_load_time (wurfl_handle wHandle, wurfl_device_handle dHandle);
static const char *ha_wurfl_get_wurfl_normalized_useragent (wurfl_handle wHandle, wurfl_device_handle dHandle);
static const char *ha_wurfl_get_wurfl_useragent_priority (wurfl_handle wHandle, wurfl_device_handle dHandle);
static const char *(*ha_wurfl_get_property_callback(char *name)) (wurfl_handle wHandle, wurfl_device_handle dHandle);

// ordered property=>function map, suitable for binary search
static const struct {
	const char *name;
	const char *(*func)(wurfl_handle wHandle, wurfl_device_handle dHandle);
} wurfl_properties_function_map [] = {
	{"wurfl_api_version", ha_wurfl_get_wurfl_api_version},
	{"wurfl_engine_target", ha_wurfl_get_wurfl_engine_target}, // kept for backward conf file compat
	{"wurfl_id", ha_wurfl_get_wurfl_id },
	{"wurfl_info", ha_wurfl_get_wurfl_info },
	{"wurfl_isdevroot", ha_wurfl_get_wurfl_isdevroot},
	{"wurfl_last_load_time", ha_wurfl_get_wurfl_last_load_time},
	{"wurfl_normalized_useragent", ha_wurfl_get_wurfl_normalized_useragent},
	{"wurfl_root_id", ha_wurfl_get_wurfl_root_id},
	{"wurfl_useragent", ha_wurfl_get_wurfl_useragent},
	{"wurfl_useragent_priority", ha_wurfl_get_wurfl_useragent_priority }, // kept for backward conf file compat
};
static const int HA_WURFL_PROPERTIES_NBR = 10;

typedef struct {
	struct list list;
	wurfl_data_t data;
} wurfl_information_t;

typedef struct {
	struct list list;
	char *patch_file_path;
} wurfl_patches_t;

typedef struct {
	struct sample *wsmp;
	char header_value[HA_WURFL_MAX_HEADER_LENGTH + 1];
} ha_wurfl_header_t;

/*
 * configuration parameters parsing functions
 */
static int ha_wurfl_cfg_data_file(char **args, int section_type, struct proxy *curpx,
                                  struct proxy *defpx, const char *file, int line,
                                  char **err)
{

	if (*(args[1]) == 0) {
		memprintf(err, "WURFL: %s expects a value.\n", args[0]);
		return -1;
	}

	global_wurfl.data_file = strdup(args[1]);
	return 0;
}

static int ha_wurfl_cfg_cache(char **args, int section_type, struct proxy *curpx,
                              struct proxy *defpx, const char *file, int line,
                              char **err)
{
	if (*(args[1]) == 0) {
		memprintf(err, "WURFL: %s expects a value.\n", args[0]);
		return -1;
	}

	global_wurfl.cache_size = strdup(args[1]);
	return 0;
}

static int ha_wurfl_cfg_engine_mode(char **args, int section_type, struct proxy *curpx,
                                    struct proxy *defpx, const char *file, int line,
                                    char **err)
{
	// kept for backward conf file compat
	return 0;
}

static int ha_wurfl_cfg_information_list_separator(char **args, int section_type, struct proxy *curpx,
                                                   struct proxy *defpx, const char *file, int line,
                                                   char **err)
{
	if (*(args[1]) == 0) {
		memprintf(err, "WURFL: %s expects a single character.\n", args[0]);
		return -1;
	}

	if (strlen(args[1]) > 1) {
		memprintf(err, "WURFL: %s expects a single character, got %s.\n", args[0], args[1]);
		return -1;
	}

	global_wurfl.information_list_separator = *args[1];
	return 0;
}

static int ha_wurfl_cfg_information_list(char **args, int section_type, struct proxy *curpx,
                                         struct proxy *defpx, const char *file, int line,
                                         char **err)
{
	int argIdx = 1;
	wurfl_information_t *wi;

	if (*(args[argIdx]) == 0) {
		memprintf(err, "WURFL: %s expects a value.\n", args[0]);
		return -1;
	}

	while (*(args[argIdx])) {
		wi = calloc(1, sizeof(*wi));

		if (wi == NULL) {
			memprintf(err, "WURFL: Error allocating memory for %s element.\n", args[0]);
			return -1;
		}

		wi->data.name = strdup(args[argIdx]);
		wi->data.type = HA_WURFL_DATA_TYPE_UNKNOWN;
		wi->data.func_callback = NULL;
		LIST_ADDQ(&global_wurfl.information_list, &wi->list);
		++argIdx;
	}

	return 0;
}

static int ha_wurfl_cfg_patch_file_list(char **args, int section_type, struct proxy *curpx,
                                        struct proxy *defpx, const char *file, int line,
                                        char **err)
{
	int argIdx = 1;
	wurfl_patches_t *wp;

	if (*(args[argIdx]) == 0) {
		memprintf(err, "WURFL: %s expects a value.\n", args[0]);
		return -1;
	}

	while (*(args[argIdx])) {
		wp = calloc(1, sizeof(*wp));

		if (wp == NULL) {
			memprintf(err, "WURFL: Error allocating memory for %s element.\n", args[0]);
			return -1;
		}

		wp->patch_file_path = strdup(args[argIdx]);
		LIST_ADDQ(&global_wurfl.patch_file_list, &wp->list);
		++argIdx;
	}

	return 0;
}

static int ha_wurfl_cfg_useragent_priority(char **args, int section_type, struct proxy *curpx,
                                           struct proxy *defpx, const char *file, int line,
                                           char **err)
{
	// this feature is deprecated, keeping only not to break compatibility
	// with old configuration files.
	return 0;
}

/*
 * module init / deinit functions. Returns 0 if OK, or a combination of ERR_*.
 */

static int ha_wurfl_init(void)
{
	wurfl_information_t *wi;
	wurfl_patches_t *wp;
	wurfl_data_t * wn;
	int wurfl_result_code = WURFL_OK;
	int len;

	// wurfl-data-file not configured, WURFL is not used so don't try to
	// configure it.
	if (global_wurfl.data_file == NULL)
		return 0;

	ha_notice("WURFL: Loading module v.%s\n", HA_WURFL_MODULE_VERSION);
	// creating WURFL handler
	global_wurfl.handle = wurfl_create();

	if (global_wurfl.handle == NULL) {
		ha_warning("WURFL: Engine handler creation failed\n");
		return ERR_WARN;
	}

	ha_notice("WURFL: Engine handler created - API version %s\n", wurfl_get_api_version() );

	// set wurfl data file
	if (wurfl_set_root(global_wurfl.handle, global_wurfl.data_file) != WURFL_OK) {
		ha_warning("WURFL: Engine setting root file failed - %s\n", wurfl_get_error_message(global_wurfl.handle));
		return ERR_WARN;
	}

	ha_notice("WURFL: Engine root file set to %s\n", global_wurfl.data_file);
	// just a log to inform which separator char has to be used
	ha_notice("WURFL: Information list separator set to '%c'\n", global_wurfl.information_list_separator);

	// load wurfl data needed ( and filter whose are supposed to be capabilities )
	if (LIST_ISEMPTY(&global_wurfl.information_list)) {
		ha_warning("WURFL: missing wurfl-information-list parameter in global configuration\n");
		return ERR_WARN;
	} else {
		// ebtree initialization
		global_wurfl.btree = EB_ROOT;

		// checking if informations are valid WURFL data ( cap, vcaps, properties )
		list_for_each_entry(wi, &global_wurfl.information_list, list) {
			// check if information is already loaded looking into btree
			if (ebst_lookup(&global_wurfl.btree, wi->data.name) == NULL) {
				if ((wi->data.func_callback = (PROP_CALLBACK_FUNC) ha_wurfl_get_property_callback(wi->data.name)) != NULL) {
					wi->data.type = HA_WURFL_DATA_TYPE_PROPERTY;
#ifdef WURFL_DEBUG
					ha_notice("WURFL: [%s] is a valid wurfl data [property]\n",wi->data.name);
#endif
				} else if (wurfl_has_virtual_capability(global_wurfl.handle, wi->data.name)) {
					wi->data.type = HA_WURFL_DATA_TYPE_VCAP;
#ifdef WURFL_DEBUG
					ha_notice("WURFL: [%s] is a valid wurfl data [virtual capability]\n",wi->data.name);
#endif
				} else {
					// by default a cap type is assumed to be and we control it on engine load
					wi->data.type = HA_WURFL_DATA_TYPE_CAP;

					if (wurfl_add_requested_capability(global_wurfl.handle, wi->data.name) != WURFL_OK) {
						ha_warning("WURFL: capability filtering failed - %s\n", wurfl_get_error_message(global_wurfl.handle));
						return ERR_WARN;
					}

					ha_notice("WURFL: [%s] treated as wurfl capability. Will check its validity later, on engine load\n",wi->data.name);
				}

				// ebtree insert here
				len = strlen(wi->data.name);

				wn = malloc(sizeof(wurfl_data_t) + len + 1);

				if (wn == NULL) {
					ha_warning("WURFL: Error allocating memory for information tree element.\n");
					return ERR_WARN;
				}

				wn->name = wi->data.name;
				wn->type = wi->data.type;
				wn->func_callback = wi->data.func_callback;
				memcpy(wn->nd.key, wi->data.name, len);
				wn->nd.key[len] = 0;

				if (!ebst_insert(&global_wurfl.btree, &wn->nd)) {
					ha_warning("WURFL: [%s] not inserted in btree\n",wn->name);
					return ERR_WARN;
				}

			} else {
#ifdef WURFL_DEBUG
				ha_notice("WURFL: [%s] already loaded\n",wi->data.name);
#endif
			}

		}

	}


	// adding WURFL patches if needed
	if (!LIST_ISEMPTY(&global_wurfl.patch_file_list)) {

		list_for_each_entry(wp, &global_wurfl.patch_file_list, list) {
			if (wurfl_add_patch(global_wurfl.handle, wp->patch_file_path) != WURFL_OK) {
				ha_warning("WURFL: Engine adding patch file failed - %s\n", wurfl_get_error_message(global_wurfl.handle));
				return ERR_WARN;
			}
			ha_notice("WURFL: Engine patch file added %s\n", wp->patch_file_path);

		}

	}

	// setting cache provider if specified in cfg, otherwise let engine choose
	if (global_wurfl.cache_size != NULL) {
		if (strpbrk(global_wurfl.cache_size, ",") != NULL) {
			wurfl_result_code = wurfl_set_cache_provider(global_wurfl.handle, WURFL_CACHE_PROVIDER_DOUBLE_LRU, global_wurfl.cache_size) ;
		} else {
			if (strcmp(global_wurfl.cache_size, "0")) {
				wurfl_result_code = wurfl_set_cache_provider(global_wurfl.handle, WURFL_CACHE_PROVIDER_LRU, global_wurfl.cache_size) ;
			} else {
				wurfl_result_code = wurfl_set_cache_provider(global_wurfl.handle, WURFL_CACHE_PROVIDER_NONE, 0);
			}

		}

		if (wurfl_result_code != WURFL_OK) {
			ha_warning("WURFL: Setting cache to [%s] failed - %s\n", global_wurfl.cache_size, wurfl_get_error_message(global_wurfl.handle));
			return ERR_WARN;
		}

		ha_notice("WURFL: Cache set to [%s]\n", global_wurfl.cache_size);
	}

	// loading WURFL engine
	if (wurfl_load(global_wurfl.handle) != WURFL_OK) {
		ha_warning("WURFL: Engine load failed - %s\n", wurfl_get_error_message(global_wurfl.handle));
		return ERR_WARN;
	}

	ha_notice("WURFL: Engine loaded\n");
	ha_notice("WURFL: Module load completed\n");
	return 0;
}

static void ha_wurfl_deinit(void)
{
	wurfl_information_t *wi, *wi2;
	wurfl_patches_t *wp, *wp2;

	send_log(NULL, LOG_NOTICE, "WURFL: Unloading module v.%s\n", HA_WURFL_MODULE_VERSION);
	wurfl_destroy(global_wurfl.handle);
	global_wurfl.handle = NULL;
	free(global_wurfl.data_file);
	global_wurfl.data_file = NULL;
	free(global_wurfl.cache_size);
	global_wurfl.cache_size = NULL;

	list_for_each_entry_safe(wi, wi2, &global_wurfl.information_list, list) {
		LIST_DEL(&wi->list);
		free(wi);
	}

	list_for_each_entry_safe(wp, wp2, &global_wurfl.patch_file_list, list) {
		LIST_DEL(&wp->list);
		free(wp);
	}

	send_log(NULL, LOG_NOTICE, "WURFL: Module unloaded\n");
}

static int ha_wurfl_get_all(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	wurfl_device_handle dHandle;
	struct buffer *temp;
	wurfl_information_t *wi;
	ha_wurfl_header_t wh;
	struct channel *chn;
	struct htx *htx;

	ha_wurfl_log("WURFL: starting ha_wurfl_get_all\n");

	chn = (smp->strm ? &smp->strm->req : NULL);
	htx = smp_prefetch_htx(smp, chn, 1);
	if (!htx)
		return 0;

	wh.wsmp = smp;

	dHandle = wurfl_lookup(global_wurfl.handle, &ha_wurfl_retrieve_header, &wh);

	temp = get_trash_chunk();
	chunk_reset(temp);

	if (!dHandle) {
		ha_wurfl_log("WURFL: unable to retrieve device from request %s\n", wurfl_get_error_message(global_wurfl.handle));
		goto wurfl_get_all_completed;
	}

	list_for_each_entry(wi, &global_wurfl.information_list, list) {

		switch(wi->data.type) {
		case HA_WURFL_DATA_TYPE_UNKNOWN :
			ha_wurfl_log("WURFL: %s is of an %s type\n", wi->data.name, HA_WURFL_DATA_TYPE_UNKNOWN_STRING);
#ifdef WURFL_HEADER_WITH_DETAILS
			// write WURFL property type and name before its value...
			chunk_appendf(temp, "%s=%s", HA_WURFL_DATA_TYPE_UNKNOWN_STRING, wi->data.name);
#endif
			break;
		case HA_WURFL_DATA_TYPE_CAP :
			ha_wurfl_log("WURFL: %s is a %s\n", wi->data.name, HA_WURFL_DATA_TYPE_CAP_STRING);
#ifdef WURFL_HEADER_WITH_DETAILS
			// write WURFL property type and name before its value...
			chunk_appendf(temp, "%s=%s=", HA_WURFL_DATA_TYPE_CAP_STRING, wi->data.name);
#endif
			chunk_appendf(temp, "%s", wurfl_device_get_capability(dHandle, wi->data.name));
			break;
		case HA_WURFL_DATA_TYPE_VCAP :
			ha_wurfl_log("WURFL: %s is a %s\n", wi->data.name, HA_WURFL_DATA_TYPE_VCAP_STRING);
#ifdef WURFL_HEADER_WITH_DETAILS
			// write WURFL property type and name before its value...
			chunk_appendf(temp, "%s=%s=", HA_WURFL_DATA_TYPE_VCAP_STRING, wi->data.name);
#endif
			chunk_appendf(temp, "%s", wurfl_device_get_virtual_capability(dHandle, wi->data.name));
			break;
		case HA_WURFL_DATA_TYPE_PROPERTY :
			ha_wurfl_log("WURFL: %s is a %s\n", wi->data.name, HA_WURFL_DATA_TYPE_PROPERTY_STRING);
#ifdef WURFL_HEADER_WITH_DETAILS
			// write WURFL property type and name before its value...
			chunk_appendf(temp, "%s=%s=", HA_WURFL_DATA_TYPE_PROPERTY_STRING, wi->data.name);
#endif
			chunk_appendf(temp, "%s", wi->data.func_callback(global_wurfl.handle, dHandle));
			break;
		}

		// append wurfl-information-list-separator
		chunk_appendf(temp, "%c", global_wurfl.information_list_separator);
	}

wurfl_get_all_completed:

	wurfl_device_destroy(dHandle);
	smp->data.u.str.area = temp->area;
	smp->data.u.str.data = temp->data;

	// remove trailing wurfl-information-list-separator
	if (temp->data) {
		temp->area[temp->data] = '\0';
		--smp->data.u.str.data;
	}

	smp->data.type = SMP_T_STR;
	return 1;
}

static int ha_wurfl_get(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	wurfl_device_handle dHandle;
	struct buffer *temp;
	wurfl_data_t *wn = NULL;
	struct ebmb_node *node;
	ha_wurfl_header_t wh;
	int i = 0;
	struct channel *chn;
	struct htx *htx;

	ha_wurfl_log("WURFL: starting ha_wurfl_get\n");

	chn = (smp->strm ? &smp->strm->req : NULL);
	htx = smp_prefetch_htx(smp, chn, 1);
	if (!htx)
		return 0;

	wh.wsmp = smp;

	dHandle = wurfl_lookup(global_wurfl.handle, &ha_wurfl_retrieve_header, &wh);

	temp = get_trash_chunk();
	chunk_reset(temp);

	if (!dHandle) {
		ha_wurfl_log("WURFL: unable to retrieve device from request %s\n", wurfl_get_error_message(global_wurfl.handle));
		goto wurfl_get_completed;
	}

	while (args[i].data.str.area) {
		node = ebst_lookup(&global_wurfl.btree, args[i].data.str.area);

		if (node) {

			wn = container_of(node, wurfl_data_t, nd);

			switch(wn->type) {
			case HA_WURFL_DATA_TYPE_UNKNOWN :
				ha_wurfl_log("WURFL: %s is of an %s type\n", wn->name, HA_WURFL_DATA_TYPE_UNKNOWN_STRING);
#ifdef WURFL_HEADER_WITH_DETAILS
				// write WURFL property type and name before its value...
				chunk_appendf(temp, "%s=%s", HA_WURFL_DATA_TYPE_UNKNOWN_STRING, wn->name);
#endif
				break;
			case HA_WURFL_DATA_TYPE_CAP :
				ha_wurfl_log("WURFL: %s is a %s\n", wn->name, HA_WURFL_DATA_TYPE_CAP_STRING);
#ifdef WURFL_HEADER_WITH_DETAILS
				// write WURFL property type and name before its value...
				chunk_appendf(temp, "%s=%s=", HA_WURFL_DATA_TYPE_CAP_STRING, wn->name);
#endif
				chunk_appendf(temp, "%s", wurfl_device_get_capability(dHandle, wn->name));
				break;
			case HA_WURFL_DATA_TYPE_VCAP :
				ha_wurfl_log("WURFL: %s is a %s\n", wn->name, HA_WURFL_DATA_TYPE_VCAP_STRING);
#ifdef WURFL_HEADER_WITH_DETAILS
				// write WURFL property type and name before its value...
				chunk_appendf(temp, "%s=%s=", HA_WURFL_DATA_TYPE_VCAP_STRING, wn->name);
#endif
				chunk_appendf(temp, "%s", wurfl_device_get_virtual_capability(dHandle, wn->name));
				break;
			case HA_WURFL_DATA_TYPE_PROPERTY :
				ha_wurfl_log("WURFL: %s is a %s\n", wn->name, HA_WURFL_DATA_TYPE_PROPERTY_STRING);
#ifdef WURFL_HEADER_WITH_DETAILS
				// write WURFL property type and name before its value...
				chunk_appendf(temp, "%s=%s=", HA_WURFL_DATA_TYPE_PROPERTY_STRING, wn->name);
#endif
				chunk_appendf(temp, "%s", wn->func_callback(global_wurfl.handle, dHandle));
				break;
			}

			// append wurfl-information-list-separator
			chunk_appendf(temp, "%c", global_wurfl.information_list_separator);

		} else {
			ha_wurfl_log("WURFL: %s not in wurfl-information-list \n",
				     args[i].data.str.area);
		}

		i++;
	}

wurfl_get_completed:

	wurfl_device_destroy(dHandle);
	smp->data.u.str.area = temp->area;
	smp->data.u.str.data = temp->data;

	// remove trailing wurfl-information-list-separator
	if (temp->data) {
		temp->area[temp->data] = '\0';
		--smp->data.u.str.data;
	}

	smp->data.type = SMP_T_STR;
	return 1;
}

static struct cfg_kw_list wurflcfg_kws = {{ }, {
		{ CFG_GLOBAL, "wurfl-data-file", ha_wurfl_cfg_data_file },
		{ CFG_GLOBAL, "wurfl-information-list-separator", ha_wurfl_cfg_information_list_separator },
		{ CFG_GLOBAL, "wurfl-information-list", ha_wurfl_cfg_information_list },
		{ CFG_GLOBAL, "wurfl-patch-file", ha_wurfl_cfg_patch_file_list },
		{ CFG_GLOBAL, "wurfl-cache-size", ha_wurfl_cfg_cache },
		{ CFG_GLOBAL, "wurfl-engine-mode", ha_wurfl_cfg_engine_mode },
		{ CFG_GLOBAL, "wurfl-useragent-priority", ha_wurfl_cfg_useragent_priority },
		{ 0, NULL, NULL },
	}
};

INITCALL1(STG_REGISTER, cfg_register_keywords, &wurflcfg_kws);

/* Note: must not be declared <const> as its list will be overwritten */
static struct sample_fetch_kw_list fetch_kws = {ILH, {
		{ "wurfl-get-all", ha_wurfl_get_all, 0, NULL, SMP_T_STR, SMP_USE_HRQHV },
		{ "wurfl-get", ha_wurfl_get, ARG12(1,STR,STR,STR,STR,STR,STR,STR,STR,STR,STR,STR,STR), NULL, SMP_T_STR, SMP_USE_HRQHV },
		{ NULL, NULL, 0, 0, 0 },
	}
};

INITCALL1(STG_REGISTER, sample_register_fetches, &fetch_kws);

/* Note: must not be declared <const> as its list will be overwritten */
static struct sample_conv_kw_list conv_kws = {ILH, {
		{ NULL, NULL, 0, 0, 0 },
	}
};

INITCALL1(STG_REGISTER, sample_register_convs, &conv_kws);

// WURFL properties wrapper functions
static const char *ha_wurfl_get_wurfl_root_id (wurfl_handle wHandle, wurfl_device_handle dHandle)
{
	if (wurfl_device_get_root_id(dHandle))
		return wurfl_device_get_root_id(dHandle);
	else
		return "";
}

static const char *ha_wurfl_get_wurfl_id (wurfl_handle wHandle, wurfl_device_handle dHandle)
{
	return wurfl_device_get_id(dHandle);
}

static const char *ha_wurfl_get_wurfl_isdevroot (wurfl_handle wHandle, wurfl_device_handle dHandle)
{
	if (wurfl_device_is_actual_device_root(dHandle))
		return HA_WURFL_ISDEVROOT_TRUE;
	else
		return HA_WURFL_ISDEVROOT_FALSE;
}

static const char *ha_wurfl_get_wurfl_useragent (wurfl_handle wHandle, wurfl_device_handle dHandle)
{
	return wurfl_device_get_original_useragent(dHandle);
}

static const char *ha_wurfl_get_wurfl_api_version (wurfl_handle wHandle, wurfl_device_handle dHandle)
{
	return wurfl_get_api_version();
}

static const char *ha_wurfl_get_wurfl_engine_target (wurfl_handle wHandle, wurfl_device_handle dHandle)
{
	return "default";
}

static const char *ha_wurfl_get_wurfl_info (wurfl_handle wHandle, wurfl_device_handle dHandle)
{
	return wurfl_get_wurfl_info(wHandle);
}

static const char *ha_wurfl_get_wurfl_last_load_time (wurfl_handle wHandle, wurfl_device_handle dHandle)
{
	return wurfl_get_last_load_time_as_string(wHandle);
}

static const char *ha_wurfl_get_wurfl_normalized_useragent (wurfl_handle wHandle, wurfl_device_handle dHandle)
{
	return wurfl_device_get_normalized_useragent(dHandle);
}

static const char *ha_wurfl_get_wurfl_useragent_priority (wurfl_handle wHandle, wurfl_device_handle dHandle)
{
	return "default";
}

// call function for WURFL properties
static const char *(*ha_wurfl_get_property_callback(char *name)) (wurfl_handle wHandle, wurfl_device_handle dHandle)
{
	int position;
	int begin = 0;
	int end = HA_WURFL_PROPERTIES_NBR - 1;
	int cond = 0;

	while(begin <= end) {
		position = (begin + end) / 2;

		if((cond = strcmp(wurfl_properties_function_map[position].name, name)) == 0) {
			ha_wurfl_log("WURFL: ha_wurfl_get_property_callback match %s\n", wurfl_properties_function_map[position].name );
			return wurfl_properties_function_map[position].func;
		} else if(cond < 0)
			begin = position + 1;
		else
			end = position - 1;

	}

	return NULL;
}

static const char *ha_wurfl_retrieve_header(const char *header_name, const void *wh)
{
	struct sample *smp;
	struct channel *chn;
	struct htx *htx;
	struct http_hdr_ctx ctx;
	struct ist name;
	int header_len = HA_WURFL_MAX_HEADER_LENGTH;

	smp =  ((ha_wurfl_header_t *)wh)->wsmp;
	chn = (smp->strm ? &smp->strm->req : NULL);

	ha_wurfl_log("WURFL: retrieve header (HTX) request [%s]\n", header_name);

	//the header is searched from the beginning
	ctx.blk = NULL;

	// We could skip this chek since ha_wurfl_retrieve_header is called from inside
	// ha_wurfl_get()/ha_wurfl_get_all() that already perform the same check
	// We choose to keep it in case ha_wurfl_retrieve_header will be called directly
	htx = smp_prefetch_htx(smp, chn, 1);
	if (!htx) {
		return NULL;
	}

	name.ptr = (char *)header_name;
	name.len = strlen(header_name);

	// If 4th param is set, it works on full-line headers in whose comma is not a delimiter but is
	// part of the syntax
	if (!http_find_header(htx, name, &ctx, 1)) {
		return NULL;
	}

	if (header_len > ctx.value.len)
		header_len = ctx.value.len;

	strncpy(((ha_wurfl_header_t *)wh)->header_value, ctx.value.ptr, header_len);

	((ha_wurfl_header_t *)wh)->header_value[header_len] = '\0';

	ha_wurfl_log("WURFL: retrieve header request returns [%s]\n", ((ha_wurfl_header_t *)wh)->header_value);
	return ((ha_wurfl_header_t *)wh)->header_value;
}

static void ha_wurfl_register_build_options()
{
	const char *ver = wurfl_get_api_version();
	char *ptr = NULL;

	memprintf(&ptr, "Built with WURFL support (%sversion %s)",
		  strcmp(ver, "1.11.2.100") ? "" : "dummy library ",
		  ver);
	hap_register_build_opts(ptr, 1);
}

REGISTER_POST_CHECK(ha_wurfl_init);
REGISTER_POST_DEINIT(ha_wurfl_deinit);
INITCALL0(STG_REGISTER, ha_wurfl_register_build_options);
