#include <stdio.h>

#include <common/cfgparse.h>
#include <common/chunk.h>
#include <proto/arg.h>
#include <proto/log.h>
#include <proto/sample.h>
#include <import/xxhash.h>
#include <import/lru.h>

#include <import/51d.h>

struct _51d_property_names {
	struct list list;
	char *name;
};

static struct lru64_head *_51d_lru_tree = NULL;
static unsigned long long _51d_lru_seed;

static int _51d_data_file(char **args, int section_type, struct proxy *curpx,
                          struct proxy *defpx, const char *file, int line,
                          char **err)
{
	if (*(args[1]) == 0) {
		memprintf(err,
		          "'%s' expects a filepath to a 51Degrees trie or pattern data file.",
		          args[0]);
		return -1;
	}

	if (global._51degrees.data_file_path)
		free(global._51degrees.data_file_path);
	global._51degrees.data_file_path = strdup(args[1]);

	return 0;
}

static int _51d_property_name_list(char **args, int section_type, struct proxy *curpx,
                                  struct proxy *defpx, const char *file, int line,
                                  char **err)
{
	int cur_arg = 1;
	struct _51d_property_names *name;

	if (*(args[cur_arg]) == 0) {
		memprintf(err,
		          "'%s' expects at least one 51Degrees property name.",
		          args[0]);
		return -1;
	}

	while (*(args[cur_arg])) {
		name = calloc(1, sizeof(struct _51d_property_names));
		name->name = strdup(args[cur_arg]);
		LIST_ADDQ(&global._51degrees.property_names, &name->list);
		++cur_arg;
	}

	return 0;
}

static int _51d_property_separator(char **args, int section_type, struct proxy *curpx,
                                   struct proxy *defpx, const char *file, int line,
                                   char **err)
{
	if (*(args[1]) == 0) {
		memprintf(err,
		          "'%s' expects a single character.",
		          args[0]);
		return -1;
	}
	if (strlen(args[1]) > 1) {
		memprintf(err,
		          "'%s' expects a single character, got '%s'.",
		          args[0], args[1]);
		return -1;
	}

	global._51degrees.property_separator = *args[1];

	return 0;
}

static int _51d_cache_size(char **args, int section_type, struct proxy *curpx,
                           struct proxy *defpx, const char *file, int line,
                           char **err)
{
	if (*(args[1]) == 0) {
		memprintf(err,
		          "'%s' expects a positive numeric value.",
		          args[0]);
		return -1;
	}

	global._51degrees.cache_size = atoi(args[1]);
	if (global._51degrees.cache_size < 0) {
		memprintf(err,
		          "'%s' expects a positive numeric value, got '%s'.",
		          args[0], args[1]);
		return -1;
	}

	return 0;
}

static int _51d_conv(const struct arg *args, struct sample *smp, void *private)
{
	int i;
	char no_data[] = "NoData";  /* response when no data could be found */
	struct chunk *temp;
#ifdef FIFTYONEDEGREES_H_PATTERN_INCLUDED
	int j, found;
	const char* property_name;
	fiftyoneDegreesWorkset* ws; /* workset for detection */
#endif
#ifdef FIFTYONEDEGREES_H_TRIE_INCLUDED
	int device_offset;
	int property_index;
#endif
	struct lru64 *lru = NULL;

	/* Look in the list. */
	if (_51d_lru_tree) {
		unsigned long long seed = _51d_lru_seed ^ (long)args;

		lru = lru64_get(XXH64(smp->data.str.str, smp->data.str.len, seed),
		                _51d_lru_tree, global._51degrees.data_file_path, 0);
		if (lru && lru->domain) {
			smp->flags |= SMP_F_CONST;
			smp->data.str.str = lru->data;
			smp->data.str.len = strlen(smp->data.str.str);
			return 1;
		}
	}

#ifdef FIFTYONEDEGREES_H_PATTERN_INCLUDED
	/* Create workset. This will later contain detection results. */
	ws = fiftyoneDegreesCreateWorkset(&global._51degrees.data_set);
	if (!ws)
		return 0;
#endif

	/* Duplicate the data and remove the "const" flag before device detection. */
	if (!smp_dup(smp))
		return 0;

	smp->data.str.str[smp->data.str.len] = '\0';

	/* Perform detection. */
#ifdef FIFTYONEDEGREES_H_PATTERN_INCLUDED
	fiftyoneDegreesMatch(ws, smp->data.str.str);
#endif
#ifdef FIFTYONEDEGREES_H_TRIE_INCLUDED
	device_offset = fiftyoneDegreesGetDeviceOffset(smp->data.str.str);
#endif

	i = 0;
	temp = get_trash_chunk();

	/* Loop through property names passed to the filter and fetch them from the dataset. */
	while (args[i].data.str.str) {
		/* Try to find request property in dataset. */
#ifdef FIFTYONEDEGREES_H_PATTERN_INCLUDED
		found = 0;
		for (j = 0; j < ws->dataSet->requiredPropertyCount; j++) {
			property_name = fiftyoneDegreesGetPropertyName(ws->dataSet, ws->dataSet->requiredProperties[j]);
			if (strcmp(property_name, args[i].data.str.str) == 0) {
				found = 1;
				fiftyoneDegreesSetValues(ws, j);
				chunk_appendf(temp, "%s", fiftyoneDegreesGetValueName(ws->dataSet, *ws->values));
				break;
			}
		}
		if (!found) {
			chunk_appendf(temp, "%s", no_data);
		}
#endif
#ifdef FIFTYONEDEGREES_H_TRIE_INCLUDED
		property_index = fiftyoneDegreesGetPropertyIndex(args[i].data.str.str);
		if (property_index > 0) {
			chunk_appendf(temp, "%s", fiftyoneDegreesGetValue(device_offset, property_index));
		}
		else {
			chunk_appendf(temp, "%s", no_data);
		}
#endif
		/* Add separator. */
		chunk_appendf(temp, "%c", global._51degrees.property_separator);
		++i;
	}

	if (temp->len) {
		--temp->len;
		temp->str[temp->len] = '\0';
	}

	smp->data.str.str = temp->str;
	smp->data.str.len = strlen(smp->data.str.str);

#ifdef FIFTYONEDEGREES_H_PATTERN_INCLUDED
	fiftyoneDegreesFreeWorkset(ws);
#endif

	if (lru) {
		smp->flags |= SMP_F_CONST;
		lru64_commit(lru, strdup(smp->data.str.str), global._51degrees.data_file_path, 0, free);
	}

	return 1;
}

int init_51degrees(void)
{
	int i = 0;
	struct chunk *temp;
	struct _51d_property_names *name;
	char **_51d_property_list = NULL;
	fiftyoneDegreesDataSetInitStatus _51d_dataset_status = DATA_SET_INIT_STATUS_NOT_SET;

	if (!LIST_ISEMPTY(&global._51degrees.property_names)) {
		i = 0;
		list_for_each_entry(name, &global._51degrees.property_names, list)
			++i;
		_51d_property_list = calloc(i, sizeof(char *));

		i = 0;
		list_for_each_entry(name, &global._51degrees.property_names, list)
			_51d_property_list[i++] = name->name;
	}

#ifdef FIFTYONEDEGREES_H_PATTERN_INCLUDED
	_51d_dataset_status = fiftyoneDegreesInitWithPropertyArray(global._51degrees.data_file_path, &global._51degrees.data_set, _51d_property_list, i);
#endif
#ifdef FIFTYONEDEGREES_H_TRIE_INCLUDED
	_51d_dataset_status = fiftyoneDegreesInitWithPropertyArray(global._51degrees.data_file_path, _51d_property_list, i);
#endif

	temp = get_trash_chunk();
	chunk_reset(temp);

	switch (_51d_dataset_status) {
		case DATA_SET_INIT_STATUS_SUCCESS:
			break;
		case DATA_SET_INIT_STATUS_INSUFFICIENT_MEMORY:
			chunk_printf(temp, "Insufficient memory.");
			break;
		case DATA_SET_INIT_STATUS_CORRUPT_DATA:
#ifdef FIFTYONEDEGREES_H_PATTERN_INCLUDED
			chunk_printf(temp, "Corrupt data file. Check that the data file provided is uncompressed and Pattern data format.");
#endif
#ifdef FIFTYONEDEGREES_H_TRIE_INCLUDED
			chunk_printf(temp, "Corrupt data file. Check that the data file provided is uncompressed and Trie data format.");
#endif
			break;
		case DATA_SET_INIT_STATUS_INCORRECT_VERSION:
#ifdef FIFTYONEDEGREES_H_PATTERN_INCLUDED
			chunk_printf(temp, "Incorrect version. Check that the data file provided is uncompressed and Pattern data format.");
#endif
#ifdef FIFTYONEDEGREES_H_TRIE_INCLUDED
			chunk_printf(temp, "Incorrect version. Check that the data file provided is uncompressed and Trie data format.");
#endif
			break;
		case DATA_SET_INIT_STATUS_FILE_NOT_FOUND:
			chunk_printf(temp, "File not found.");
			break;
		case DATA_SET_INIT_STATUS_NOT_SET:
			chunk_printf(temp, "Data set not initialised.");
			break;
	}
	if (_51d_dataset_status != DATA_SET_INIT_STATUS_SUCCESS) {
		if (temp->len)
			Alert("51Degrees Setup - Error reading 51Degrees data file. %s\n", temp->str);
		else
			Alert("51Degrees Setup - Error reading 51Degrees data file.\n");
		exit(1);
	}
	free(_51d_property_list);

	_51d_lru_seed = random();
	if (global._51degrees.cache_size)
		_51d_lru_tree = lru64_new(global._51degrees.cache_size);

	return 0;
}

void deinit_51degrees(void)
{
	struct _51d_property_names *_51d_prop_name, *_51d_prop_nameb;

#ifdef FIFTYONEDEGREES_H_PATTERN_INCLUDED
	fiftyoneDegreesDestroy(&global._51degrees.data_set);
#endif
#ifdef FIFTYONEDEGREES_H_TRIE_INCLUDED
	fiftyoneDegreesDestroy();
#endif

	free(global._51degrees.data_file_path); global._51degrees.data_file_path = NULL;
	list_for_each_entry_safe(_51d_prop_name, _51d_prop_nameb, &global._51degrees.property_names, list) {
		LIST_DEL(&_51d_prop_name->list);
		free(_51d_prop_name);
	}

	while (lru64_destroy(_51d_lru_tree));
}

static struct cfg_kw_list _51dcfg_kws = {{ }, {
	{ CFG_GLOBAL, "51degrees-data-file", _51d_data_file },
	{ CFG_GLOBAL, "51degrees-property-name-list", _51d_property_name_list },
	{ CFG_GLOBAL, "51degrees-property-separator", _51d_property_separator },
	{ CFG_GLOBAL, "51degrees-cache-size", _51d_cache_size },
	{ 0, NULL, NULL },
}};

/* Note: must not be declared <const> as its list will be overwritten */
static struct sample_conv_kw_list conv_kws = {ILH, {
	{ "51d", _51d_conv, ARG5(1,STR,STR,STR,STR,STR), NULL, SMP_T_STR, SMP_T_STR },
	{ NULL, NULL, 0, 0, 0 },
}};

__attribute__((constructor))
static void __51d_init(void)
{
	/* register sample fetch and format conversion keywords */
	sample_register_convs(&conv_kws);
	cfg_register_keywords(&_51dcfg_kws);
}
