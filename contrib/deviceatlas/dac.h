#ifndef MOBI_DA_DAC_H
#define MOBI_DA_DAC_H

/**
 * @file dac.h
 * @author Afilias Technologies
 *
 * @brief API main header file
 */

#include <sys/types.h>
#include <limits.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdarg.h>

#ifndef __cplusplus
#ifndef true
#ifdef HAVE_NO_BUILTIN__BOOL
typedef int _Bool;
#endif
#define bool _Bool

#define true   1
#define false  0
#endif
#endif

#define MOBI_DA_MAJOR 2
#define MOBI_DA_MINOR 1
#define MOBI_DA_DUMMY_LIBRARY 1


/**
 * @brief All values returned by the API have one of these types.
 * da_getprop*() return data in the appropriate C type for the given da_type.
 */
enum da_type {
    DA_TYPE_NONE,
    DA_TYPE_BOOLEAN,
    DA_TYPE_INTEGER,
    DA_TYPE_NUMBER,
    DA_TYPE_STRING,
    DA_TYPE_ARRAY,
    DA_TYPE_OBJECT,
    DA_TYPE_NULL
};

/**
 * Any method that returns a da_status may potentially fail for one of these reasons.
 * XXX: Error reporting needs to be improved.
 */
enum da_status {
    DA_OK,              /* Success. */
    DA_INVALID_JSON,    /* The JSON format is invalid, or the content is unexpected in a given context. */
    DA_OVERFLOW,        /* Overflow occurred. Note this is used to indicate an unfinished string parse in JSON */
    DA_FORMAT_ERROR,    /* The data supplied is formatted incorrectly. */
    DA_NOMEM,           /* There was not enough space to complete the operation */
    DA_SYS,             /* A system error occurred - consult the OS for more details (eg, check errno) */
    DA_NOTIMPL,         /* This method is not implemented */
    DA_NOTFOUND,        /* The requested item was not found. */
    DA_REGEXBAD,        /* An invalid regex was provided. */
    DA_NOMORE,          /* Used to indicate the end of an iterator. */
    DA_INVALID_COOKIE,  /* Cookie value supplied was invalid */
    DA_INVALID_TYPE,    /* A value of an unexpected type was found. */
    DA_INTERNAL_ERROR,
    DA_STATUS_LAST      /* Placeholder to indicate highest possible error value. (value will change as API matures) */
};

enum da_severity {
    DA_SEV_FATAL, /* The operation will not continue, and the operation will return an error. */
    DA_SEV_ERROR, /* An error occurred, but the API call will return at least some valid information */
    DA_SEV_WARN,  /* An unexpected event occured, but the system dealt with it */
    DA_SEV_INFO   /* An informational message. */
};
/* Forward references to tagged types */
struct atlas_image;
struct da_atlas;
struct da_deviceinfo;
struct da_jsonparser;
struct da_node;
struct da_propset;
union da_value;
struct da_evidence;
struct da_bitset;
struct da_allocator;
struct da_config;

/**
 * @brief Primary types of the interface.
 * Primary types used by API client.
 * Non-typedef structures and unions are considered private to the API.
 *
 */
typedef enum da_severity da_severity_t; /* A severity for the error callback. */
typedef enum da_status da_status_t; /* An error code - returned from most API calls. */
typedef da_status_t (*da_setpos_fn)(void *ctx, off_t off); /* callback provided to API to rewind input stream */
typedef enum da_type da_type_t; /* A value type (integer, string, etc) */

/**
 * @brief An operation on an atlas involves converting a set of evidence strings into a set of property/value pairs.
 * The ID for a particular type of evidence is extract from the atlas (eg, for a specific HTTP header, use:
 *
 * da_evidence_id_t evidence = da_atlas_header_evidence_id(atlas, "User-Agent");
 *
 */
typedef int da_evidence_id_t;

/**
 * @brief The search result encompasses a key/value set. Keys are handles retrieved via
 * _either_ da_atlas_getpropid() or da_getpropid().
 * Some search results may have keys not available when the atlas is opened (eg,
 * when the name of the property itself is contained within the evidence)
 * Such properties by necessity are given a "local" da_propid_t
 *
 * You can ensure any properties you are interested in get a global propid by
 * passing a list of interesting named properties to da_atlas_open()
 */
typedef int da_propid_t;
typedef size_t (*da_read_fn)(void *ctx, size_t maxlen, char *ptr);
typedef struct da_atlas da_atlas_t;
typedef struct da_deviceinfo da_deviceinfo_t;
typedef struct da_evidence da_evidence_t;
typedef struct da_jsonparser da_jsonparser_t;
typedef struct da_node da_node_t;
typedef struct da_property_decl da_property_decl_t;
typedef struct da_propset da_propset_t;
typedef struct da_config da_config_t;
typedef void *(*da_alloc_fn)(void *ctx, size_t);
typedef void (*da_free_fn)(void *ctx, void *);
typedef void *(*da_realloc_fn)(void *ctx, void *, size_t);
typedef void (*da_errorfunc_t)(da_severity_t severity, da_status_t status, const char *msg, va_list args);


/* Manifest constants. */
enum {
    /*
     * used as the initial guess for the compiled size of an atlas.
     * If atlas sizes grow more beyond this, it can be expanded to avoid multiple scans of the data.
     */
    DA_INITIAL_MEMORY_ESTIMATE = 1024 * 1024 * 14
};

struct da_config {
    unsigned int ua_props;
    unsigned int lang_props;
    unsigned int __reserved[14]; /* enough reserved keywords for future use */
};

/**
 * Functional interface.
 */

/**
 * @brief Initialize process to use the DA API.
 */
void da_init(void);


/**
 * @brief Release all resources used by the API
 */
void da_fini(void);

/**
 * @brief User-supplied callback to be invoked with information about an error.
 * Note this may use thread-local storage etc to store the info on return from the current call
 * It is guaranteed that an error-reporting function returning an error-code will have called
 * this function at least once.
 * @param callback function
 */
void da_seterrorfunc(da_errorfunc_t callback);

/**
 * @brief Given a specific HTTP header, return the associated ID for that header.
 * When passing evidence to the API, its type is identified using its da_evidince_id_t.
 * @param atlas atlas instance
 * @param header_name Header's name
 * @return evidence id
 */
da_evidence_id_t da_atlas_header_evidence_id(const da_atlas_t *atlas, const char *header_name);
/**
 * @brief Return the associated ID of the client side properties evidence
 * @param atlas Atlas instance
 * @return evidence id
 */
da_evidence_id_t da_atlas_clientprop_evidence_id(const da_atlas_t *atlas);
/**
 * @brief Return the associated ID of the accept language header evidence
 * @param atlas Atlas instance
 * @return evidence id
 */
da_evidence_id_t da_atlas_accept_language_evidence_id(const da_atlas_t *atlas);

/**
 * @brief readfn should present JSON content from ctx.
 * atlasp points to an uninitialized da_atlas structure.
 * Result is a compiled atlas at atlasp.
 * Result is allocated via normal memory-allocation methods, malloc/calloc/realloc, so should be
 * Free'd with free()
 * XXX TODO: Change this to take a da_allocator
 * @param ctx pointer given to read the json file
 * @param readfn function pointer, set accordingly to the attended given pointer
 * @param setposfn function pointer
 * @param ptr Pointer dynamically allocated if the json parsing happened normally
 * @param len size of the atlas image
 * @return status of atlas compilation
 */
da_status_t da_atlas_compile(void *ctx, da_read_fn readfn, da_setpos_fn setposfn, void **ptr, size_t *len);

/**
 * @brief opens a previously compiled atlas for operations. extra_props will be available in calls to
 * da_getpropid on the atlas, and if generated by the search, the ID will be consistent across
 * different calls to search.
 * Properties added by a search that are neither in the compiled atlas, nor in the extra_props list
 * Are assigned an ID within the context that is not transferrable through different search results
 * within the same atlas.
 * @param atlas Atlas instance
 * @param extra_props properties
 * @param ptr given pointer from previously compiled atlas
 * @param pos atlas image size
 * @return status of atlas data opening
 */
da_status_t da_atlas_open(da_atlas_t *atlas, da_property_decl_t *extra_props, const void *ptr, size_t pos);

/**
 * @brief Release any resources associated with the atlas structure atlas, which was previously generated from
 * da_read_atlas or da_compile_atlas.
 * @param atlas instance
 */
void da_atlas_close(da_atlas_t *atlas);

/**
 * @brief Find device properties given a set of evidence.
 * Search results are returned in da_deviceinfo_t, and must be cleaned using da_close
 * "Evidence" is an array of length count, of string data tagged with an evidence ID.
 * @param atlas Atlas instance
 * @param info Device info
 * @param ev Array of evidences
 * @param count Number of evidence given
 * @return status of the search
 */
da_status_t da_searchv(const da_atlas_t *atlas, da_deviceinfo_t *info, da_evidence_t *ev, size_t count);

/**
 * @brief As da_search, but unrolls the evidence array into variable arguments for simpler calling
 * convention with known evidence types.
 * varargs are pairs of (da_evidence_id, string), terminated with da_evidence_id DA_END
 * @code da_search(&myAtlas, &deviceInfo, da_get_header_evidence_id("User-Agent"),
 * "Mozilla/5.0 (Linux...", DA_END);
 * @endcode
 * @param atlas Atlas instance
 * @param info given device info which holds on device properties
 * @param pairs of evidence id / evidence value
 * @return status of the search
 */
da_status_t da_search(const da_atlas_t *atlas, da_deviceinfo_t *info, ...);

/**
 * @brief After finishing with a search result, release resources associated with it.
 * @param info Device info previously allocated by search functions
 */
void da_close(da_deviceinfo_t *info);

/**
 * @brief Given a property name (Eg, "displayWidth"), return the property ID associated with it for the
 * specified atlas.
 * @param atlas Atlas instance
 * @param propname Property name
 * @param propid Property id
 * @return status of the property id search
 */
da_status_t da_atlas_getpropid(const da_atlas_t *atlas, const char *propname, da_propid_t *propid);

/**
 * @brief Given a property ID, return the type of that property.
 * @code
 *   da_getproptype(&myAtlas, da_getpropid(&myAtlas, "displayWidth"), &propertyType);
 *   assert(propertyType == DA_TYPE_INT);
 * @endcode
 * @param atlas Atlas instance
 * @param propid Property id
 * @param type Type id of the property
 * @return status of the type id search
 */
da_status_t da_atlas_getproptype(const da_atlas_t *atlas, da_propid_t propid, da_type_t *type);

/**
 * @brief Given a property ID, return the name of that property.
 * @code
 *   da_atlas_getpropname(&myAtlas, da_getpropid(&myAtlas, "displayWidth"), &propertyName);
 *   assert(strcmp("displayWidth", propertyName) == 0);
 * @endcode
 * @param atlas Atlas instance
 * @param propid property id
 * @param propname property name returned
 * @return status of the property name search
 */
da_status_t da_atlas_getpropname(const da_atlas_t *atlas, da_propid_t propid, const char **propname);


/**
 * @brief Given an atlas instance, return its counters + the builtins
 * @code
 *   da_atlas_getpropcount(&myAtlas);
 * @endcode
 * @param atlas Atlas instance
 * @return counters
 */
size_t da_atlas_getpropcount(const da_atlas_t *atlas);

/**
 * @brief Given an atlas instance, set the detection config
 * @param atlas Atlas instance
 * @param config instance
 */
void da_atlas_setconfig(da_atlas_t *atlas, da_config_t *config);

/**
 * @brief Given a search result, find the value of a specific property.
 * @code
 *   long displayWidth; // width of display in pixels.
 *   da_getpropinteger(&deviceInfo, da_getpropid(&myAtlas, "displayWidth"), &displayWidth);
 * @endcode
 * String contents are owned by the search result, and are valid until the search is closed.
 */
/**
 * @brief returns a property value as a string from a given string typed property id
 * @param info Device info
 * @param propid Property id
 * @param value Value of the property
 * @return status of property value search
 */
da_status_t da_getpropstring(const da_deviceinfo_t *info, da_propid_t propid, const char **value);
/**
 * @brief returns a property value as a long from a given long typed property id
 * @param info Device info
 * @param propid Property id
 * @param value Value of the property
 * @return status of property value search
 */
da_status_t da_getpropinteger(const da_deviceinfo_t *info, da_propid_t propid, long *value);
/**
 * @brief returns a property value as a boolean from a given boolean typed property id
 * @param info Device info
 * @param propid Property id
 * @param value Value of the property
 * @return status of property value search
 */
da_status_t da_getpropboolean(const da_deviceinfo_t *info, da_propid_t propid, bool *value);
/**
 * @brief returns a property value as a float from a given float typed property id
 * @param info Device info
 * @param propid Property id
 * @param value Value of the property
 * @return status of property value search
 */
da_status_t da_getpropfloat(const da_deviceinfo_t *info, da_propid_t propid, double *value);

/**
 * @brief Some properties may not be not known to the atlas before the search commences.
 * Such properties cannot have a da_propid_t assigned to them on the atlas, but will
 * have a local property assigned during search. The name and type of such properties
 * can be discovered here.
 *
 * Properties that are used in the atlas source and properties specifically registered
 * with da_atlas_open() will always be assigned to a property discovered during search.
 * Therefore, if there are specific properties that you want to use, and are unsure
 * if they are in your device atlas source, registering them with da_atlas_open will
 * make access to them easier and more efficient
 */
/**
 * @brief returns the type of a given device property from the search functions
 * @param info Device info
 * @param propid Property id
 * @param type Type id
 * @return status of property type search
 */
da_status_t da_getproptype(const da_deviceinfo_t *info, da_propid_t propid, da_type_t *type);
/**
 * @brief returns the name of a given device property from the search functions
 * @param info Device info
 * @param propid Property id
 * @param propname Property name
 * @return status of property type search
 */
da_status_t da_getpropname(const da_deviceinfo_t *info, da_propid_t propid, const char **propname);

/**
 * @brief da_getfirstprop/da_getnextprop provide iteration over all properties
 * in a search result.
 * Both will return DA_OK if there is a result available, and DA_NOMORE
 * if the search is complete.
 * @code
 *
 * da_propid_t *propidp;
 * for (da_status_t status = da_getfirstprop(&result, &propidp);
 *          status == DA_OK;
 *          status = da_getnextprop(&result, &propidp)) {
 *     const char *propname;
 *     if (da_getpropname(&result, *propidp, &propname) == DA_OK)
 *         fprintf("found property %s\n", propname);
 * }
 * @endcode
 */

/**
 * @brief returns the first property from device info
 * @param info Device info
 * @param propid Property
 * @return status
 */
da_status_t da_getfirstprop(const da_deviceinfo_t *info, da_propid_t **propid);
/**
 * @brief device info properties iterator
 * @param info Device info
 * @param propid Property
 * @return status
 */
da_status_t da_getnextprop(const da_deviceinfo_t *info, da_propid_t **propid);

/**
 * @brief Report an error, as per a report from the API to the user-callback.
 * @param severity Severity level of the error
 * @param fmt format error message
 * @param va_list
 * @return status
 */
da_status_t da_reporterror(da_status_t severity, const char *fmt, ...);

/**
 * @brief returns a textual description of the type "type".
 * @param type Type id
 * @return type name
 */
const char *da_typename(da_type_t type);

/**
 * @brief returns the version from the JSON in memory
 * @param atlas
 * @return version
 */
char *da_getdataversion(da_atlas_t *atlas);

/**
 * @brief returns the date creation's timestamp from the JSON in memory
 * @param atlas
 * @return version
 */
time_t da_getdatacreation(da_atlas_t *atlas);

/**
 * @brief returns the revision's number from the JSON in memory
 * @param atlas
 * @return version
 */
int da_getdatarevision(da_atlas_t *atlas);

/**
 * @brief returns the name of a global property
 * @param atlas Atlas instance
 * @param propid Property id
 * @return property name
 */
const char *da_get_property_name(const da_atlas_t *atlas, da_propid_t propid);

/**
 * @brief returns the number of properties in a result.
 * @param info Device info
 * @return properties count
 */
size_t da_getpropcount(const da_deviceinfo_t *info);

/*
 * Details below should not be required for usage of the API
 */

/**
 * @brief Represents a usable device atlas interface.
 *
 * No user servicable parts inside: access should
 * be via the functional API.
 */
struct da_atlas {
    const struct atlas_image *image;
    struct header_evidence_entry *header_priorities;
    size_t header_evidence_count;

    struct pcre_regex_info *uar_regexes;
    size_t uar_regex_count;

    struct pcre_regex_info *replacement_regexes;
    size_t replacement_regex_count;

    da_evidence_id_t user_agent_evidence;
    da_evidence_id_t clientprops_evidence;
    da_evidence_id_t accept_language_evidence;
    da_evidence_id_t next_evidence;

    da_propset_t *properties;
    da_propid_t id_propid;
    da_propid_t id_proplang;
    da_propid_t id_proplang_locale;

    da_config_t config;

    da_deviceinfo_t **cpr_props;
    size_t cpr_count;
};

/* fixed constants. */
enum {
    DA_BUFSIZE = 16000
};

/**
 * Represents a chunk of memory. See comments on da_deviceinfo.
 * This is presented here to allow aggregation in da_deviceinfo:
 * Not for public consumption.
 */
struct da_buf {
    struct da_buf *next;
    char *cur;
    char *limit;
    char buf[DA_BUFSIZE];
};

/**
 * A callback interface for allocating memory from some source
 * Not for public consumption.
 */
struct da_allocator {
    da_alloc_fn alloc;
    da_free_fn free;
    da_realloc_fn realloc;
    void *context;
};


/**
 * Represents a search result
 * Can be used to retrieve values of known properties discovered from the evidence,
 * iterate over the properties with known values, and query property types that are
 * local to this result.
 *
 * The atlas the search is carried out on must survive any da_deviceinfo results
 * it provides.
 */
struct da_deviceinfo {
    struct da_allocator allocator;
    const da_atlas_t *atlas;   /* reference to the atlas the search was carried out on. */
    struct da_bitset *present; /* property received from tree */
    struct da_bitset *localprop; /* property was received from UAR rule or CPR */
    struct da_bitset *cprprop;  /* property was received from CPR */
    union da_value *properties; /* properties - indexed by property id. */
    da_propid_t *proplist; /* list of properties present in this result. */
    size_t propcount; /* size of proplist */
    da_propset_t *local_types; /* property descriptors local to this search result. */

    /**
     * The per-deviceinfo heap is stored here. Allocations for data in the result
     * come from the raw data in these buffers. The size of the fixed-size buffer
     * built in to da_buf is sized such that all known search results will not
     * require memory allocation via malloc()
     */
    struct da_buf *heap;
    struct da_buf initial_heap;
};

/**
 * Used to pass evidence to da_searchv()
 */
struct da_evidence {
    da_evidence_id_t key;
    char *value;
};

/**
 * Used to pass properties the API intends to query to the da_atlas_open function
 * This can be used to improve performance of lookup on properties well-known
 * to the API user, but not present in the JSON database.
 */
struct da_property_decl {
    const char *name;
    da_type_t type;
};


#endif /* DEVATLAS_DAC_H */
