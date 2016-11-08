#include <stdio.h>
#include <stdarg.h>

#include <common/cfgparse.h>
#include <common/chunk.h>
#include <common/buffer.h>
#include <proto/arg.h>
#include <proto/log.h>
#include <proto/proto_http.h>
#include <proto/sample.h>
#include <proto/wurfl.h>
#include <ebsttree.h>
#include <ebmbtree.h>

#include <wurfl/wurfl.h>


#ifdef WURFL_DEBUG
inline static void ha_wurfl_log(char * message, ...)
{
	char logbuf[256];
	va_list argp;

	va_start(argp, message);
	vsnprintf(logbuf, sizeof(logbuf), message, argp);
	va_end(argp);
	send_log(NULL, LOG_NOTICE, logbuf, NULL);
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

static const char HA_WURFL_MODULE_VERSION[] = "1.0";
static const char HA_WURFL_ISDEVROOT_FALSE[] = "FALSE";
static const char HA_WURFL_ISDEVROOT_TRUE[] = "TRUE";
static const char HA_WURFL_TARGET_ACCURACY[] = "accuracy";
static const char HA_WURFL_TARGET_PERFORMANCE[] = "performance";
static const char HA_WURFL_PRIORITY_PLAIN[] = "plain";
static const char HA_WURFL_PRIORITY_SIDELOADED_BROWSER[] = "sideloaded_browser";
static const char HA_WURFL_MIN_ENGINE_VERSION_MANDATORY[] = "1.8.0.0";

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
	{"wurfl_engine_target", ha_wurfl_get_wurfl_engine_target},
	{"wurfl_id", ha_wurfl_get_wurfl_id },
	{"wurfl_info", ha_wurfl_get_wurfl_info },
	{"wurfl_isdevroot", ha_wurfl_get_wurfl_isdevroot},
	{"wurfl_last_load_time", ha_wurfl_get_wurfl_last_load_time},
	{"wurfl_normalized_useragent", ha_wurfl_get_wurfl_normalized_useragent},
	{"wurfl_useragent", ha_wurfl_get_wurfl_useragent},
	{"wurfl_useragent_priority", ha_wurfl_get_wurfl_useragent_priority },
	{"wurfl_root_id", ha_wurfl_get_wurfl_root_id},
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

	global.wurfl.data_file = strdup(args[1]);
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

	global.wurfl.cache_size = strdup(args[1]);
	return 0;
}

static int ha_wurfl_cfg_engine_mode(char **args, int section_type, struct proxy *curpx,
                                    struct proxy *defpx, const char *file, int line,
                                    char **err)
{
	if (*(args[1]) == 0) {
		memprintf(err, "WURFL: %s expects a value.\n", args[0]);
		return -1;
	}

	if (!strcmp(args[1],HA_WURFL_TARGET_ACCURACY)) {
		global.wurfl.engine_mode = WURFL_ENGINE_TARGET_HIGH_ACCURACY;
		return 0;
	}

	if (!strcmp(args[1],HA_WURFL_TARGET_PERFORMANCE)) {
		global.wurfl.engine_mode = WURFL_ENGINE_TARGET_HIGH_PERFORMANCE;
		return 0;
	}

	memprintf(err, "WURFL: %s valid values are %s or %s.\n", args[0], HA_WURFL_TARGET_PERFORMANCE, HA_WURFL_TARGET_ACCURACY);
	return -1;
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

	global.wurfl.information_list_separator = *args[1];
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
		LIST_ADDQ(&global.wurfl.information_list, &wi->list);
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
		LIST_ADDQ(&global.wurfl.patch_file_list, &wp->list);
		++argIdx;
	}

	return 0;
}

static int ha_wurfl_cfg_useragent_priority(char **args, int section_type, struct proxy *curpx,
                                           struct proxy *defpx, const char *file, int line,
                                           char **err)
{
	if (*(args[1]) == 0) {
		memprintf(err, "WURFL: %s expects a value.\n", args[0]);
		return -1;
	}

	if (!strcmp(args[1],HA_WURFL_PRIORITY_PLAIN)) {
		global.wurfl.useragent_priority = WURFL_USERAGENT_PRIORITY_USE_PLAIN_USERAGENT;
		return 0;
	}

	if (!strcmp(args[1],HA_WURFL_PRIORITY_SIDELOADED_BROWSER)) {
		global.wurfl.useragent_priority = WURFL_USERAGENT_PRIORITY_OVERRIDE_SIDELOADED_BROWSER_USERAGENT;
		return 0;
	}

	memprintf(err, "WURFL: %s valid values are %s or %s.\n", args[0], HA_WURFL_PRIORITY_PLAIN, HA_WURFL_PRIORITY_SIDELOADED_BROWSER);
	return -1;
}

/*
 * module init / deinit functions
 */

int ha_wurfl_init(void)
{
	wurfl_information_t *wi;
	wurfl_patches_t *wp;
	wurfl_data_t * wn;
	int wurfl_result_code = WURFL_OK;
	int len;

	send_log(NULL, LOG_NOTICE, "WURFL: Loading module v.%s\n", HA_WURFL_MODULE_VERSION);
	// creating WURFL handler
	global.wurfl.handle = wurfl_create();

	if (global.wurfl.handle == NULL) {
		Warning("WURFL: Engine handler creation failed");
		send_log(NULL, LOG_WARNING, "WURFL: Engine handler creation failed\n");
		return -1;
	}

	send_log(NULL, LOG_NOTICE, "WURFL: Engine handler created - API version %s\n", wurfl_get_api_version() );

	// set wurfl data file
	if (global.wurfl.data_file == NULL) {
		Warning("WURFL: missing wurfl-data-file parameter in global configuration\n");
		send_log(NULL, LOG_WARNING, "WURFL: missing wurfl-data-file parameter in global configuration\n");
		return -1;
	}

	if (wurfl_set_root(global.wurfl.handle, global.wurfl.data_file) != WURFL_OK) {
		Warning("WURFL: Engine setting root file failed - %s\n", wurfl_get_error_message(global.wurfl.handle));
		send_log(NULL, LOG_WARNING, "WURFL: Engine setting root file failed - %s\n", wurfl_get_error_message(global.wurfl.handle));
		return -1;
	}

	send_log(NULL, LOG_NOTICE, "WURFL: Engine root file set to %s\n", global.wurfl.data_file);
	// just a log to inform which separator char has to be used
	send_log(NULL, LOG_NOTICE, "WURFL: Information list separator set to '%c'\n", global.wurfl.information_list_separator);

	// load wurfl data needed ( and filter whose are supposed to be capabilities )
	if (LIST_ISEMPTY(&global.wurfl.information_list)) {
		Warning("WURFL: missing wurfl-information-list parameter in global configuration\n");
		send_log(NULL, LOG_WARNING, "WURFL: missing wurfl-information-list parameter in global configuration\n");
		return -1;
	} else {
		// ebtree initialization
		global.wurfl.btree = EB_ROOT;

		// checking if informations are valid WURFL data ( cap, vcaps, properties )
		list_for_each_entry(wi, &global.wurfl.information_list, list) {

			// check if information is already loaded looking into btree
			if (ebst_lookup(&global.wurfl.btree, wi->data.name) == NULL) {

				if ((wi->data.func_callback = (PROP_CALLBACK_FUNC) ha_wurfl_get_property_callback(wi->data.name)) != NULL) {
					wi->data.type = HA_WURFL_DATA_TYPE_PROPERTY;
					ha_wurfl_log("WURFL: [%s] is a valid wurfl data [property]\n",wi->data.name);
				} else if (wurfl_has_virtual_capability(global.wurfl.handle, wi->data.name)) {
					wi->data.type = HA_WURFL_DATA_TYPE_VCAP;
					ha_wurfl_log("WURFL: [%s] is a valid wurfl data [virtual capability]\n",wi->data.name);
				} else {
					// by default a cap type is assumed to be and we control it on engine load
					wi->data.type = HA_WURFL_DATA_TYPE_CAP;

					if (wurfl_add_requested_capability(global.wurfl.handle, wi->data.name) != WURFL_OK) {
						Warning("WURFL: capability filtering failed - %s\n", wurfl_get_error_message(global.wurfl.handle));
						send_log(NULL, LOG_WARNING, "WURFL: capability filtering failed - %s\n", wurfl_get_error_message(global.wurfl.handle));
						return -1;
					}

					ha_wurfl_log("WURFL: [%s] treated as wurfl capability. Will check its validity later, on engine load\n",wi->data.name);
				}

				// ebtree insert here
				len = strlen(wi->data.name);

				wn = malloc(sizeof(wurfl_data_t) + len + 1);

				if (wn == NULL) {
					Warning("WURFL: Error allocating memory for information tree element.\n");
					send_log(NULL, LOG_WARNING, "WURFL: Error allocating memory for information tree element.\n");
					return -1;
				}

				wn->name = wi->data.name;
				wn->type = wi->data.type;
				wn->func_callback = wi->data.func_callback;
				memcpy(wn->nd.key, wi->data.name, len);
				wn->nd.key[len] = 0;

				if (!ebst_insert(&global.wurfl.btree, &wn->nd)) {
					Warning("WURFL: [%s] not inserted in btree\n",wn->name);
					send_log(NULL, LOG_WARNING, "WURFL: [%s] not inserted in btree\n",wn->name);
					return -1;
				}

			} else {
				ha_wurfl_log("WURFL: [%s] already loaded\n",wi->data.name);
			}

		}

	}

	// filtering mandatory capabilities if engine version < 1.8.0.0
	if (strcmp(wurfl_get_api_version(), HA_WURFL_MIN_ENGINE_VERSION_MANDATORY) < 0) {
		wurfl_capability_enumerator_handle hmandatorycapabilityenumerator;
		ha_wurfl_log("WURFL: Engine version %s < %s - Filtering mandatory capabilities\n", wurfl_get_api_version(), HA_WURFL_MIN_ENGINE_VERSION_MANDATORY);
		hmandatorycapabilityenumerator = wurfl_get_mandatory_capability_enumerator(global.wurfl.handle);

		while (wurfl_capability_enumerator_is_valid(hmandatorycapabilityenumerator)) {
			char *name = (char *)wurfl_capability_enumerator_get_name(hmandatorycapabilityenumerator);

			if (ebst_lookup(&global.wurfl.btree, name) == NULL) {

				if (wurfl_add_requested_capability(global.wurfl.handle, name) != WURFL_OK) {
					Warning("WURFL: Engine adding mandatory capability [%s] failed - %s\n", name, wurfl_get_error_message(global.wurfl.handle));
					send_log(NULL, LOG_WARNING, "WURFL: Adding mandatory capability [%s] failed - %s\n", name, wurfl_get_error_message(global.wurfl.handle));
					return -1;
				}

				ha_wurfl_log("WURFL: Mandatory capability [%s] added\n", name);
			} else {
				ha_wurfl_log("WURFL: Mandatory capability [%s] already filtered\n", name);
			}

			wurfl_capability_enumerator_move_next(hmandatorycapabilityenumerator);
		}

		wurfl_capability_enumerator_destroy(hmandatorycapabilityenumerator);
	}

	// adding WURFL patches if needed
	if (!LIST_ISEMPTY(&global.wurfl.patch_file_list)) {

		list_for_each_entry(wp, &global.wurfl.patch_file_list, list) {

			if (wurfl_add_patch(global.wurfl.handle, wp->patch_file_path) != WURFL_OK) {
				Warning("WURFL: Engine adding patch file failed - %s\n", wurfl_get_error_message(global.wurfl.handle));
				send_log(NULL, LOG_WARNING, "WURFL: Adding engine patch file failed - %s\n", wurfl_get_error_message(global.wurfl.handle));
				return -1;
			}
			send_log(NULL, LOG_NOTICE, "WURFL: Engine patch file added %s\n", wp->patch_file_path);

		}

	}

	// setting cache provider if specified in cfg, otherwise let engine choose
	if (global.wurfl.cache_size != NULL) {

		if (strpbrk(global.wurfl.cache_size, ",") != NULL) {
			wurfl_result_code = wurfl_set_cache_provider(global.wurfl.handle, WURFL_CACHE_PROVIDER_DOUBLE_LRU, global.wurfl.cache_size) ;
		} else {

			if (strcmp(global.wurfl.cache_size, "0")) {
				wurfl_result_code = wurfl_set_cache_provider(global.wurfl.handle, WURFL_CACHE_PROVIDER_LRU, global.wurfl.cache_size) ;
			} else {
				wurfl_result_code = wurfl_set_cache_provider(global.wurfl.handle, WURFL_CACHE_PROVIDER_NONE, 0);
			}

		}

		if (wurfl_result_code != WURFL_OK) {
			Warning("WURFL: Setting cache to [%s] failed - %s\n", global.wurfl.cache_size, wurfl_get_error_message(global.wurfl.handle));
			send_log(NULL, LOG_WARNING, "WURFL: Setting cache to [%s] failed - %s\n", global.wurfl.cache_size, wurfl_get_error_message(global.wurfl.handle));
			return -1;
		}

		send_log(NULL, LOG_NOTICE, "WURFL: Cache set to [%s]\n", global.wurfl.cache_size);
	}

	// setting engine mode if specified in cfg, otherwise let engine choose
	if (global.wurfl.engine_mode != -1) {

		if (wurfl_set_engine_target(global.wurfl.handle, global.wurfl.engine_mode) != WURFL_OK ) {
			Warning("WURFL: Setting engine target failed - %s\n", wurfl_get_error_message(global.wurfl.handle));
			send_log(NULL, LOG_WARNING, "WURFL: Setting engine target failed - %s\n", wurfl_get_error_message(global.wurfl.handle));
			return -1;
		}

	}

	send_log(NULL, LOG_NOTICE, "WURFL: Engine target set to [%s]\n", (global.wurfl.engine_mode == WURFL_ENGINE_TARGET_HIGH_PERFORMANCE) ? (HA_WURFL_TARGET_PERFORMANCE) : (HA_WURFL_TARGET_ACCURACY) );

	// setting ua priority if specified in cfg, otherwise let engine choose
	if (global.wurfl.useragent_priority != -1) {

		if (wurfl_set_useragent_priority(global.wurfl.handle, global.wurfl.useragent_priority) != WURFL_OK ) {
			Warning("WURFL: Setting engine useragent priority failed - %s\n", wurfl_get_error_message(global.wurfl.handle));
			send_log(NULL, LOG_WARNING, "WURFL: Setting engine useragent priority failed - %s\n", wurfl_get_error_message(global.wurfl.handle));
			return -1;
		}

	}

	send_log(NULL, LOG_NOTICE, "WURFL: Engine useragent priority set to [%s]\n", (global.wurfl.useragent_priority == WURFL_USERAGENT_PRIORITY_USE_PLAIN_USERAGENT) ? (HA_WURFL_PRIORITY_PLAIN) : (HA_WURFL_PRIORITY_SIDELOADED_BROWSER) );

	// loading WURFL engine
	if (wurfl_load(global.wurfl.handle) != WURFL_OK) {
		Warning("WURFL: Engine load failed - %s\n", wurfl_get_error_message(global.wurfl.handle));
		send_log(NULL, LOG_WARNING, "WURFL: Engine load failed - %s\n", wurfl_get_error_message(global.wurfl.handle));
		return -1;
	}

	send_log(NULL, LOG_NOTICE, "WURFL: Engine loaded\n");
	send_log(NULL, LOG_NOTICE, "WURFL: Module load completed\n");
	return 0;
}

void ha_wurfl_deinit(void)
{
	wurfl_information_t *wi, *wi2;
	wurfl_patches_t *wp, *wp2;

	send_log(NULL, LOG_NOTICE, "WURFL: Unloading module v.%s\n", HA_WURFL_MODULE_VERSION);
	wurfl_destroy(global.wurfl.handle);
	global.wurfl.handle = NULL;
	free(global.wurfl.data_file);
	global.wurfl.data_file = NULL;
	free(global.wurfl.cache_size);
	global.wurfl.cache_size = NULL;

	list_for_each_entry_safe(wi, wi2, &global.wurfl.information_list, list) {
		LIST_DEL(&wi->list);
		free(wi);
	}

	list_for_each_entry_safe(wp, wp2, &global.wurfl.patch_file_list, list) {
		LIST_DEL(&wp->list);
		free(wp);
	}

	send_log(NULL, LOG_NOTICE, "WURFL: Module unloaded\n");
}

static int ha_wurfl_get_all(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	wurfl_device_handle dHandle;
	struct chunk *temp;
	wurfl_information_t *wi;
	ha_wurfl_header_t wh;

	ha_wurfl_log("WURFL: starting ha_wurfl_get_all\n");
	wh.wsmp = smp;
	dHandle = wurfl_lookup(global.wurfl.handle, &ha_wurfl_retrieve_header, &wh);

	if (!dHandle) {
		ha_wurfl_log("WURFL: unable to retrieve device from request %s\n", wurfl_get_error_message(global.wurfl.handle));
		return 1;
	}

	temp = get_trash_chunk();
	chunk_reset(temp);

	list_for_each_entry(wi, &global.wurfl.information_list, list) {
		chunk_appendf(temp, "%c", global.wurfl.information_list_separator);

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
			chunk_appendf(temp, "%s", wi->data.func_callback(global.wurfl.handle, dHandle));
			break;
		}

	}

	wurfl_device_destroy(dHandle);
	smp->data.u.str.str = temp->str;
	smp->data.u.str.len = temp->len;
	return 1;
}

static int ha_wurfl_get(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	wurfl_device_handle dHandle;
	struct chunk *temp;
	wurfl_data_t *wn = NULL;
	struct ebmb_node *node;
	ha_wurfl_header_t wh;
	int i = 0;

	ha_wurfl_log("WURFL: starting ha_wurfl_get\n");
	wh.wsmp = smp;
	dHandle = wurfl_lookup(global.wurfl.handle, &ha_wurfl_retrieve_header, &wh);

	if (!dHandle) {
		ha_wurfl_log("WURFL: unable to retrieve device from request %s\n", wurfl_get_error_message(global.wurfl.handle));
		return 1;
	}

	temp = get_trash_chunk();
	chunk_reset(temp);

	while (args[i].data.str.str) {
		chunk_appendf(temp, "%c", global.wurfl.information_list_separator);
		node = ebst_lookup(&global.wurfl.btree, args[i].data.str.str);
		wn = container_of(node, wurfl_data_t, nd);

		if (wn) {

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
				chunk_appendf(temp, "%s", wn->func_callback(global.wurfl.handle, dHandle));
				break;
			}

		} else {
			ha_wurfl_log("WURFL: %s not in wurfl-information-list \n", args[i].data.str.str);
		}

		i++;
	}

	wurfl_device_destroy(dHandle);
	smp->data.u.str.str = temp->str;
	smp->data.u.str.len = temp->len;
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

/* Note: must not be declared <const> as its list will be overwritten */
static struct sample_fetch_kw_list fetch_kws = {ILH, {
		{ "wurfl-get-all", ha_wurfl_get_all, 0, NULL, SMP_T_STR, SMP_USE_HRQHV },
		{ "wurfl-get", ha_wurfl_get, ARG12(1,STR,STR,STR,STR,STR,STR,STR,STR,STR,STR,STR,STR), NULL, SMP_T_STR, SMP_USE_HRQHV },
		{ NULL, NULL, 0, 0, 0 },
	}
};

/* Note: must not be declared <const> as its list will be overwritten */
static struct sample_conv_kw_list conv_kws = {ILH, {
		{ NULL, NULL, 0, 0, 0 },
	}
};

__attribute__((constructor))
static void __wurfl_init(void)
{
	/* register sample fetch and format conversion keywords */
	sample_register_fetches(&fetch_kws);
	sample_register_convs(&conv_kws);
	cfg_register_keywords(&wurflcfg_kws);
}

// WURFL properties wrapper functions
static const char *ha_wurfl_get_wurfl_root_id (wurfl_handle wHandle, wurfl_device_handle dHandle)
{
	return wurfl_device_get_root_id(dHandle);
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
	return wurfl_get_engine_target_as_string(wHandle);
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
	return wurfl_get_useragent_priority_as_string(wHandle);
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
	struct hdr_idx *idx;
	struct hdr_ctx ctx;
	const struct http_msg *msg;
	int header_len = HA_WURFL_MAX_HEADER_LENGTH;

	ha_wurfl_log("WURFL: retrieve header request [%s]\n", header_name);
	smp =  ((ha_wurfl_header_t *)wh)->wsmp;
	idx = &smp->strm->txn->hdr_idx;
	msg = &smp->strm->txn->req;
	ctx.idx = 0;

	if (http_find_full_header2(header_name, strlen(header_name), msg->chn->buf->p, idx, &ctx) == 0)
		return 0;

	if (header_len > ctx.vlen)
		header_len = ctx.vlen;

	strncpy(((ha_wurfl_header_t *)wh)->header_value, ctx.line + ctx.val, header_len);
	((ha_wurfl_header_t *)wh)->header_value[header_len] = '\0';
	ha_wurfl_log("WURFL: retrieve header request returns [%s]\n", ((ha_wurfl_header_t *)wh)->header_value);
	return ((ha_wurfl_header_t *)wh)->header_value;
}
