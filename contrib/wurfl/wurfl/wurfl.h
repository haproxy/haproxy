/*
 * InFuze C API - HAPROXY Dummy library version of include
 *
 * Copyright (c) ScientiaMobile, Inc.
 * http://www.scientiamobile.com
 *
 * This software package is the property of ScientiaMobile Inc. and is licensed
 * commercially according to a contract between the Licensee and ScientiaMobile Inc. (Licensor).
 * If you represent the Licensee, please refer to the licensing agreement which has been signed
 * between the two parties. If you do not represent the Licensee, you are not authorized to use
 * this software in any way.
 *
 */

#ifndef _WURFL_H_
#define _WURFL_H_

#include <time.h>

#if defined (__GNUC__) || defined (__clang__)
#define DEPRECATED __attribute__((deprecated))
#elif defined(_MSC_VER)
#define DEPRECATED __declspec(deprecated)
#else
#pragma message("WARNING: You need to implement DEPRECATED for this compiler")
#define DEPRECATED
#endif

// WURFL error enumeration
typedef enum {
    WURFL_OK = 0,                                                   //!< no error
    WURFL_ERROR_INVALID_HANDLE = 1,                                 //!< handle passed to the function is invalid
    WURFL_ERROR_ALREADY_LOAD = 2,                                   //!< wurfl_load has already been invoked on the specific wurfl_handle
    WURFL_ERROR_FILE_NOT_FOUND = 3,                                 //!< file not found during wurfl_load or remote data file update
    WURFL_ERROR_UNEXPECTED_END_OF_FILE = 4,                         //!< unexpected end of file or parsing error during wurfl_load
    WURFL_ERROR_INPUT_OUTPUT_FAILURE = 5,                           //!< error reading stream during wurfl_load or updater accessing local updated data file
    WURFL_ERROR_DEVICE_NOT_FOUND = 6,                               //!< specified device is missing
    WURFL_ERROR_CAPABILITY_NOT_FOUND = 7,                           //!< specified capability is missing
    WURFL_ERROR_INVALID_CAPABILITY_VALUE = 8,                       //!< invalid capability value
    WURFL_ERROR_VIRTUAL_CAPABILITY_NOT_FOUND = 9,                   //!< specified virtual capability is missing
    WURFL_ERROR_CANT_LOAD_CAPABILITY_NOT_FOUND = 10,                 //!< specified capability is missing
    WURFL_ERROR_CANT_LOAD_VIRTUAL_CAPABILITY_NOT_FOUND = 11,         //!< specified virtual capability is missing
    WURFL_ERROR_EMPTY_ID = 12,                                       //!< missing id in searching device
    WURFL_ERROR_CAPABILITY_GROUP_NOT_FOUND = 13,                     //!< specified capability is missing in its group
    WURFL_ERROR_CAPABILITY_GROUP_MISMATCH = 14,                      //!< specified capability mismatch in its group
    WURFL_ERROR_DEVICE_ALREADY_DEFINED = 15,                         //!< specified device is already defined
    WURFL_ERROR_USERAGENT_ALREADY_DEFINED = 16,                      //!< specified user agent is already defined
    WURFL_ERROR_DEVICE_HIERARCHY_CIRCULAR_REFERENCE = 17,            //!< circular reference in device hierarchy
    WURFL_ERROR_UNKNOWN = 18,                                        //!< unknown error
    WURFL_ERROR_INVALID_USERAGENT_PRIORITY = 19,                     //!< specified override sideloaded browser user agent configuration not valid
    WURFL_ERROR_INVALID_PARAMETER = 20,                              //!< invalid parameter
    WURFL_ERROR_INVALID_CACHE_SIZE = 21,                             //!< specified an invalid cache size, 0 or a negative value.
    WURFL_ERROR_XML_CONSISTENCY = 22,                               //!< WURFL data file is out of date or wrong - some needed device_id/capability is missing
    WURFL_ERROR_INTERNAL = 23,                                       //!< internal error. If this is an updater issue, please enable and check updater log using wurfl_updater_set_log_path()
    WURFL_ERROR_VIRTUAL_CAPABILITY_NOT_AVAILABLE = 24,               //!< the requested virtual capability has not been licensed
    WURFL_ERROR_MISSING_USERAGENT = 25,                              // an XML device definition without mandatory UA has been detected
    WURFL_ERROR_XML_PARSE = 26,                                      // the XML data file is malformed
    WURFL_ERROR_UPDATER_INVALID_DATA_URL = 27,                       // updater data URL is missing or invalid (note: only .zip and .gz formats allowed)
    WURFL_ERROR_UPDATER_INVALID_LICENSE = 28,                        // client license is invalid, expired etc
    WURFL_ERROR_UPDATER_NETWORK_ERROR = 29,                          // updater request returned an HTTP response != 200, or SSL error, etc. Please enable and check updater log using wurfl_updater_set_log_path()
    WURFL_ERROR_ENGINE_NOT_INITIALIZED = 30,                         // prerequisite for executing an update is that the engine has been initialized (i.e., wurfl_load() has been called)
    WURFL_ERROR_UPDATER_ALREADY_RUNNING = 31,                        // wurfl_updater_start() can be called just once, when the updater is not running
    WURFL_ERROR_UPDATER_NOT_RUNNING = 32,                            // wurfl_updater_stop() can be called just once, when the updater is running
    WURFL_ERROR_UPDATER_TOO_MANY_REQUESTS = 33,                      // Updater encountered HTTP 429 error
    WURFL_ERROR_UPDATER_CMDLINE_DOWNLOADER_UNAVAILABLE = 34,         // Curl executable not found. Please check path, etc
    WURFL_ERROR_UPDATER_TIMEDOUT = 35,                               // Curl operation timed out.
    WURFL_ERROR_ROOT_NOT_SET = 36,                                   // set_root() must be called before any load() / reload() and update attempt
    WURFL_ERROR_WRONG_ENGINE_TARGET = 37,                            // set_engine_target() was called with a wrong/unrecognized parameter
    // new errors added in

    WURFL_ERROR_CANNOT_FILTER_STATIC_CAP = 38,
    WURFL_ENGINE_UNABLE_TO_ALLOCATE_MEMORY = 39,
    WURFL_ENGINE_NOT_LOADED = 40,
    WURFL_ERROR_UPDATER_CANNOT_START_THREAD = 41,
    WURFL_ERROR_ENUM_EMPTY_SET = 42,

    // update when adding errors
    WURFL_ERROR_LAST = 43
} wurfl_error;

typedef enum {
    WURFL_ENGINE_TARGET_HIGH_ACCURACY = 0,
    WURFL_ENGINE_TARGET_HIGH_PERFORMANCE = 1,
    WURFL_ENGINE_TARGET_DEFAULT = 2,
    WURFL_ENGINE_TARGET_FAST_DESKTOP_BROWSER_MATCH = 3,
} wurfl_engine_target;

typedef enum {
    WURFL_USERAGENT_PRIORITY_OVERRIDE_SIDELOADED_BROWSER_USERAGENT,
    WURFL_USERAGENT_PRIORITY_USE_PLAIN_USERAGENT,
    WURFL_USERAGENT_PRIORITY_INVALID,
} wurfl_useragent_priority;

typedef enum {
    WURFL_CACHE_PROVIDER_NONE,
    WURFL_CACHE_PROVIDER_LRU,
    WURFL_CACHE_PROVIDER_DOUBLE_LRU,
} wurfl_cache_provider;

typedef enum {
    WURFL_MATCH_TYPE_EXACT = 0,
    WURFL_MATCH_TYPE_CONCLUSIVE = 1,
    WURFL_MATCH_TYPE_RECOVERY = 2,
    WURFL_MATCH_TYPE_CATCHALL = 3,
    WURFL_MATCH_TYPE_HIGHPERFORMANCE = 4, // deprecated. See hereunder.
    WURFL_MATCH_TYPE_NONE = 5,
    WURFL_MATCH_TYPE_CACHED = 6,
    WURFL_MATCH_TYPE_FAST_DESKTOP_BROWSER_MATCH = 7
} wurfl_match_type;


typedef enum {
    WURFL_UPDATER_FREQ_DAILY = 0,
    WURFL_UPDATER_FREQ_WEEKLY = 1,
} wurfl_updater_frequency;


#ifdef __cplusplus
extern "C" {
#endif

// typedef struct _we_h * wurfl_handle;
// typedef struct _en_t * wurfl_enum_handle;
// typedef struct _en_t * wurfl_device_capability_enumerator_handle;
// typedef struct _en_t * wurfl_capability_enumerator_handle;
// typedef struct _en_t * wurfl_device_id_enumerator_handle;
// typedef struct _md_t * wurfl_device_handle;

typedef void * wurfl_handle;
typedef void * wurfl_enum_handle;
typedef void * wurfl_device_capability_enumerator_handle;
typedef void * wurfl_capability_enumerator_handle;
typedef void * wurfl_device_id_enumerator_handle;
typedef void * wurfl_device_handle;

const char *wurfl_get_api_version(void);
wurfl_handle wurfl_create(void);
void wurfl_destroy(wurfl_handle handle);

// NEW : enable/set api logfile
wurfl_error wurfl_set_log_path(wurfl_handle hwurfl, const char *log_path);
// allow writing user stuff on logs : mesg will be prepended by a "USER LOG :" string
wurfl_error wurfl_log_print(wurfl_handle hwurfl, char *msg);

// Errors

const char *wurfl_get_error_message(wurfl_handle hwurfl);
wurfl_error wurfl_get_error_code(wurfl_handle hwurfl);
int wurfl_has_error_message(wurfl_handle hwurfl);
// deprecated
void wurfl_clear_error_message(wurfl_handle hwurfl);

const char *wurfl_get_wurfl_info(wurfl_handle hwurfl);
wurfl_error wurfl_set_root(wurfl_handle hwurfl, const char* root);
wurfl_error wurfl_add_patch(wurfl_handle hwurfl, const char *patch);
wurfl_error wurfl_add_requested_capability(wurfl_handle hwurfl, const char *requested_capability);
DEPRECATED wurfl_error wurfl_set_engine_target(wurfl_handle hwurfl, wurfl_engine_target target);
DEPRECATED wurfl_engine_target wurfl_get_engine_target(wurfl_handle hwurfl);
DEPRECATED const char *wurfl_get_engine_target_as_string(wurfl_handle hwurfl);
DEPRECATED wurfl_error wurfl_set_useragent_priority(wurfl_handle hwurfl, wurfl_useragent_priority useragent_priority);
DEPRECATED wurfl_useragent_priority wurfl_get_useragent_priority(wurfl_handle hwurfl);
DEPRECATED const char *wurfl_get_useragent_priority_as_string(wurfl_handle hwurfl);
wurfl_error wurfl_set_cache_provider(wurfl_handle hwurfl, wurfl_cache_provider cache_provider, const char *config);
wurfl_error wurfl_load(wurfl_handle hwurfl);
struct tm *wurfl_get_last_load_time(wurfl_handle hwurfl);
const char *wurfl_get_last_load_time_as_string(wurfl_handle hwurfl);
int wurfl_has_capability(wurfl_handle hwurfl, const char *capability);
int wurfl_has_virtual_capability(wurfl_handle hwurfl, const char *virtual_capability);

/*
 * enumerators
 */

/*
 * new enumerators implementation
 *
 * a selector is used to indicate which enumerator we needed
   WURFL_ENUM_VIRTUAL_CAPABILITIES, WURFL_ENUM_STATIC_CAPABILITIES, WURFL_ENUM_MANDATORY_CAPABILITIES, WURFL_ENUM_WURFLID,
 */

typedef enum {
    WURFL_ENUM_STATIC_CAPABILITIES,
    WURFL_ENUM_VIRTUAL_CAPABILITIES,
    WURFL_ENUM_MANDATORY_CAPABILITIES,
    WURFL_ENUM_WURFLID,
} wurfl_enum_type;

wurfl_enum_handle wurfl_enum_create(wurfl_handle, wurfl_enum_type);
const char *wurfl_enum_get_name(wurfl_enum_handle handle);
int wurfl_enum_is_valid(wurfl_enum_handle handle);
void wurfl_enum_move_next(wurfl_enum_handle handle);
void wurfl_enum_destroy(wurfl_enum_handle handle);

/* deprecated enumerators */
// virtual caps
//DEPRECATED wurfl_capability_enumerator_handle wurfl_get_virtual_capability_enumerator(wurfl_handle hwurfl);
wurfl_capability_enumerator_handle wurfl_get_virtual_capability_enumerator(wurfl_handle hwurfl);

// all mandatories
//DEPRECATED wurfl_capability_enumerator_handle wurfl_get_mandatory_capability_enumerator(wurfl_handle hwurfl);
wurfl_capability_enumerator_handle wurfl_get_mandatory_capability_enumerator(wurfl_handle hwurfl);

// all capabilities
//DEPRECATED wurfl_capability_enumerator_handle wurfl_get_capability_enumerator(wurfl_handle hwurfl);
wurfl_capability_enumerator_handle wurfl_get_capability_enumerator(wurfl_handle hwurfl);
//DEPRECATED const char *wurfl_capability_enumerator_get_name(wurfl_capability_enumerator_handle hwurflcapabilityenumeratorhandle);
const char *wurfl_capability_enumerator_get_name(wurfl_capability_enumerator_handle hwurflcapabilityenumeratorhandle);
//DEPRECATED int wurfl_capability_enumerator_is_valid(wurfl_capability_enumerator_handle handle);
int wurfl_capability_enumerator_is_valid(wurfl_capability_enumerator_handle handle);
//DEPRECATED void wurfl_capability_enumerator_move_next(wurfl_capability_enumerator_handle handle);
void wurfl_capability_enumerator_move_next(wurfl_capability_enumerator_handle handle);
//DEPRECATED void wurfl_capability_enumerator_destroy(wurfl_capability_enumerator_handle handle);
void wurfl_capability_enumerator_destroy(wurfl_capability_enumerator_handle handle);

// device id enumerator
//DEPRECATED wurfl_device_id_enumerator_handle wurfl_get_device_id_enumerator(wurfl_handle hwurfl);
wurfl_device_id_enumerator_handle wurfl_get_device_id_enumerator(wurfl_handle hwurfl);
//DEPRECATED const char *wurfl_device_id_enumerator_get_device_id(wurfl_device_id_enumerator_handle hwurfldeviceidenumeratorhandle);
const char *wurfl_device_id_enumerator_get_device_id(wurfl_device_id_enumerator_handle hwurfldeviceidenumeratorhandle);
//DEPRECATED int wurfl_device_id_enumerator_is_valid(wurfl_device_id_enumerator_handle handle);
int wurfl_device_id_enumerator_is_valid(wurfl_device_id_enumerator_handle handle);
//DEPRECATED void wurfl_device_id_enumerator_move_next(wurfl_device_id_enumerator_handle handle);
void wurfl_device_id_enumerator_move_next(wurfl_device_id_enumerator_handle handle);
//DEPRECATED void wurfl_device_id_enumerator_destroy(wurfl_device_id_enumerator_handle handle);
void wurfl_device_id_enumerator_destroy(wurfl_device_id_enumerator_handle handle);

/*
 * deprecated device enumerators
 */

//DEPRECATED wurfl_device_capability_enumerator_handle wurfl_device_get_capability_enumerator(wurfl_device_handle hwurfldevice);
wurfl_device_capability_enumerator_handle wurfl_device_get_capability_enumerator(wurfl_device_handle hwurfldevice);
//DEPRECATED wurfl_device_capability_enumerator_handle wurfl_device_get_virtual_capability_enumerator(wurfl_device_handle hwurfldevice);
wurfl_device_capability_enumerator_handle wurfl_device_get_virtual_capability_enumerator(wurfl_device_handle hwurfldevice);
//DEPRECATED const char *wurfl_device_capability_enumerator_get_name(wurfl_device_capability_enumerator_handle);
const char *wurfl_device_capability_enumerator_get_name(wurfl_device_capability_enumerator_handle);
//DEPRECATED int wurfl_device_capability_enumerator_is_valid(wurfl_device_capability_enumerator_handle);
int wurfl_device_capability_enumerator_is_valid(wurfl_device_capability_enumerator_handle);
//DEPRECATED void wurfl_device_capability_enumerator_move_next(wurfl_device_capability_enumerator_handle);
void wurfl_device_capability_enumerator_move_next(wurfl_device_capability_enumerator_handle);
//DEPRECATED void wurfl_device_capability_enumerator_destroy(wurfl_device_capability_enumerator_handle);
void wurfl_device_capability_enumerator_destroy(wurfl_device_capability_enumerator_handle);

//DEPRECATED const char *wurfl_device_capability_enumerator_get_value(wurfl_device_capability_enumerator_handle);
const char *wurfl_device_capability_enumerator_get_value(wurfl_device_capability_enumerator_handle);
//DEPRECATED int wurfl_device_capability_enumerator_get_value_as_int(wurfl_device_capability_enumerator_handle hwurfldevicecapabilityenumeratorhandle);
int wurfl_device_capability_enumerator_get_value_as_int(wurfl_device_capability_enumerator_handle hwurfldevicecapabilityenumeratorhandle);
//DEPRECATED int wurfl_device_capability_enumerator_get_value_as_bool(wurfl_device_capability_enumerator_handle hwurfldevicecapabilityenumeratorhandle);
int wurfl_device_capability_enumerator_get_value_as_bool(wurfl_device_capability_enumerator_handle hwurfldevicecapabilityenumeratorhandle);


/*
 * Device lookup methods
 */

typedef const char *(*wurfl_header_retrieve_callback)(const char *header_name, const void *callback_data);

wurfl_device_handle wurfl_lookup(wurfl_handle hwurfl, wurfl_header_retrieve_callback header_retrieve_callback, const void *header_retrieve_callback_data);
wurfl_device_handle wurfl_lookup_useragent(wurfl_handle hwurfl, const char *useragent);
wurfl_device_handle wurfl_get_device(wurfl_handle hwurfl, const char *deviceid);
wurfl_device_handle wurfl_get_device_with_headers(wurfl_handle hwurfl, const char *deviceid, wurfl_header_retrieve_callback header_retrieve_callback, const void *header_retrieve_callback_data);

/*
 * device related methods
 */

const char *wurfl_device_get_id(wurfl_device_handle hwurfldevice);
const char *wurfl_device_get_root_id(wurfl_device_handle hwurfldevice);
const char *wurfl_device_get_useragent(wurfl_device_handle hwurfldevice);
const char *wurfl_device_get_original_useragent(wurfl_device_handle hwurfldevice);
const char *wurfl_device_get_normalized_useragent(wurfl_device_handle hwurfldevice);
int wurfl_device_is_actual_device_root(wurfl_device_handle hwurfldevice);
wurfl_match_type wurfl_device_get_match_type(wurfl_device_handle hwurfldevice);
const char *wurfl_device_get_matcher_name(wurfl_device_handle hwurfldevice);
const char *wurfl_device_get_bucket_matcher_name(wurfl_device_handle hwurfldevice);
void wurfl_device_destroy(wurfl_device_handle handle);


/*
 * static capability, virtual capability methods
 */

int wurfl_device_has_capability(wurfl_device_handle hwurfldevice, const char *capability);

const char *wurfl_device_get_capability(wurfl_device_handle hwurfldevice, const char *capability);
int wurfl_device_get_capability_as_int(wurfl_device_handle hwurfldevice, const char *capability);
int wurfl_device_get_capability_as_bool(wurfl_device_handle hwurfldevice, const char *capability);

int wurfl_device_has_virtual_capability(wurfl_device_handle hwurfldevice, const char *capability);

const char *wurfl_device_get_virtual_capability(wurfl_device_handle hwurfldevice, const char *capability);
int wurfl_device_get_virtual_capability_as_int(wurfl_device_handle hwurfldevice, const char *capability);
int wurfl_device_get_virtual_capability_as_bool(wurfl_device_handle hwurfldevice, const char *capability);

/*
 * static capability, virtual capability NEW methods
 */

const char *wurfl_device_get_static_cap(wurfl_device_handle hwdev, const char *cap, wurfl_error *err);
int wurfl_device_get_static_cap_as_int(wurfl_device_handle hwdev, const char *cap, wurfl_error *err);
int wurfl_device_get_static_cap_as_bool(wurfl_device_handle hwdev, const char *cap, wurfl_error *err);

const char *wurfl_device_get_virtual_cap(wurfl_device_handle hwdev, const char *vcap, wurfl_error *err);
int wurfl_device_get_virtual_cap_as_int(wurfl_device_handle hwdev, const char *vcap, wurfl_error *err);
int wurfl_device_get_virtual_cap_as_bool(wurfl_device_handle hwdev, const char *vcap, wurfl_error *err);

/*
 * Updater methods
 */

// Instruct the updater module to log to file any operation/error. If not used, the updater will not log anything.
// Returns: WURLF_OK if no errors, WURFL_ERROR_INPUT_OUTPUT_FAILURE if the log file cannot be created (no write access rights?)
// or if you try to reopen the log file anywhere else, i.e. this call can be made just once, any attempt to reopen a different log file will fail.
wurfl_error wurfl_updater_set_log_path(wurfl_handle hwurfl, const char *log_path);

// Set remote data file URL for downloading via internal updater. Will execute various validation tests
// eventually returning WURFL_ERROR_UPDATER_XXX errors for various error conditions and logging detailed infos if
// update logger is enabled.
wurfl_error wurfl_updater_set_data_url(wurfl_handle hwurfl, const char *data_url);

// Set the updater frequency of automatic updates. Will run a background task with given update frequency.
wurfl_error wurfl_updater_set_data_frequency(wurfl_handle hwurfl, wurfl_updater_frequency freq);

// Set updater timeouts.
// There are two timeouts, both in miliseconds : connection timeout and operation timeout.
// The values are mapped to CURL --connect-timeout and --max-time parameters
// (after millisecs-to-secs conversion). Note that CURL sub millisecond timeouts don't work for
// lack of a way to specify decimal values for timeout to curl (using 0.05 for example fails to work
// on docker machines with "POSIX" locale installed.
// Connection timeout has a default value of 10 seconds (10000 ms) and refers only to connection phase. Passing 0 will use CURL value "no timeout used".
// Data transfer timeout has a default value of 600 seconds (600000 ms). Passing 0 will use CURL default value "no timeout used"
// So, pass 0 to either parameter to set it to "no timeout used"
// Pass -1 to either parameter to use default values (10 secs, 600 secs)
// The specified timeouts (if any) are used just in the synchronous (i.e., wurfl_updater_runonce()) API call.
// The asynchronous background updater always runs with default (CURL) timeouts (i.e., it will wait "as long as needed" for a new data file to be downloaded)
wurfl_error wurfl_updater_set_data_url_timeouts(wurfl_handle hwurfl, int connection_timeout, int data_transfer_timeout);

// Call a synchronous update. This is a blocking call and will execute the whole process
// of downloading the new data file, checking for correctness, replacing the data file and restarting the engine.
// Will keep all old configurations (patches, cache, etc)
// Returns WURLF_OK if no errors,
// or WURFL_ERROR_UPDATER_XXX errors for various error conditions, eventually logging detailed infos if
// update logger is enabled.
wurfl_error wurfl_updater_runonce(wurfl_handle hwurfl);

// Start the asynchronous update thread. Can be called just once when the updater is stopped;
// Subsequent/wrong calls will return WURFL_ERROR_UPDATER_ALREADY_RUNNING
// Will also return WURFL_ERROR_UPDATER_XXX errors for various initialization error conditions (see above), eventually logging detailed infos if
// update logger is enabled.
// On success will return WURLF_OK
wurfl_error wurfl_updater_start(wurfl_handle hwurfl);

// Stop the asynchronous update thread. Can be called just once when the updater is started;
// Subsequent/wrong calls will return WURFL_ERROR_UPDATER_NOT_RUNNING.
// On success will return WURLF_OK
wurfl_error wurfl_updater_stop(wurfl_handle hwurfl);

// Reload and reboot the engine with the given data file. Basically, the same process of a wurfl_updater_runonce but without the file download.
// Will synchronously load the new root testing for errors, restart the engine with the new data file and overwrite the old data file with the new one.
// Will keep old configuration (patches, cache, etc)
// Preconditions: wurfl_set_root() and wurfl_load() must have been called and the new root must be of the same kind (i.e, same extension) as the actual root
// You can force a reload of the actual set_root() file passing NULL as the newroot
wurfl_error wurfl_updater_reload_root(wurfl_handle hwurfl, const char *newroot);

// Alternative API for passing headers to lookup functions

// An opaque type representing a name/value headers map
// You can create, fill and destroy this object directly.
typedef struct _ih_h * wurfl_important_header_handle;
wurfl_important_header_handle wurfl_important_header_create(wurfl_handle);
wurfl_error wurfl_important_header_set(wurfl_important_header_handle, const char *name, const char *value);
void wurfl_important_header_destroy(wurfl_important_header_handle);

// Alternative lookup functions using the above wurfl_important_header_handle object.
// Once called, you can destroy the wurfl_important_header_handle object. Headers values are cached internally in the wurfl_device_handle.
wurfl_device_handle wurfl_lookup_with_important_header(wurfl_handle, wurfl_important_header_handle);
wurfl_device_handle wurfl_get_device_with_important_header(wurfl_handle, const char *deviceid, wurfl_important_header_handle);

// Enumerator of all headers that should be passed to a lookup function. Returns a null-termninated list of const char*
//
// Example usage:
//
//      const char** importantHeadersNames = wurfl_get_important_header_names();
//      int i = 0;
//      while (importantHeadersNames[i])
//      {
//          printf("important header %i: %s\n", i, headerNames[i]);
//          i++;
//      }
const char **wurfl_get_important_header_names(void);

// classic WURFL iterator version of the enumerator hereabove.
typedef void *wurfl_important_header_enumerator_handle;
wurfl_important_header_enumerator_handle wurfl_get_important_header_enumerator(wurfl_handle hwurfl);
void wurfl_important_header_enumerator_destroy(wurfl_important_header_enumerator_handle);
const char *wurfl_important_header_enumerator_get_value(wurfl_important_header_enumerator_handle);
int wurfl_important_header_enumerator_is_valid(wurfl_important_header_enumerator_handle);
void wurfl_important_header_enumerator_move_next(wurfl_important_header_enumerator_handle);

#ifdef __cplusplus
}
#endif

#endif // _WURFL_H_
