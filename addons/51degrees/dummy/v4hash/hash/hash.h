/* *********************************************************************
 * This Original Work is copyright of 51 Degrees Mobile Experts Limited.
 * Copyright 2022 51 Degrees Mobile Experts Limited, Davidson House,
 * Forbury Square, Reading, Berkshire, United Kingdom RG1 3EU.
 *
 * This Original Work is the subject of the following patents and patent
 * applications, owned by 51 Degrees Mobile Experts Limited of 5 Charlotte
 * Close, Caversham, Reading, Berkshire, United Kingdom RG4 7BY:
 * European Patent No. 3438848; and
 * United States Patent No. 10,482,175.
 *
 * This Original Work is licensed under the European Union Public Licence
 * (EUPL) v.1.2 and is subject to its terms as set out below.
 *
 * If a copy of the EUPL was not distributed with this file, You can obtain
 * one at https://opensource.org/licenses/EUPL-1.2.
 *
 * The 'Compatible Licences' set out in the Appendix to the EUPL (as may be
 * amended by the European Commission) shall be deemed incompatible for
 * the purposes of the Work and the provisions of the compatibility
 * clause in Article 5 of the EUPL shall not apply.
 *
 * If using the Work as, or as part of, a network application, by
 * including the attribution notice(s) required under Article 5 of the EUPL
 * in the end user terms of the application under an appropriate heading,
 * such notice(s) shall fulfill the requirements of that article.
 * ********************************************************************* */

/* *********************************************************************
 * Dummy library for HAProxy. This does not function, and is designed
 * solely for HAProxy testing purposes.
 * *********************************************************************/
#ifndef FIFTYONE_DEGREES_HASH_INCLUDED
#define FIFTYONE_DEGREES_HASH_INCLUDED

#ifndef FIFTYONEDEGREES_DUMMY_LIB
#define FIFTYONEDEGREES_DUMMY_LIB
#endif

#include <stdlib.h>
#include <inttypes.h>

typedef int bool;
enum { false, true };

typedef unsigned char byte;

typedef enum e_fiftyone_degrees_status_code {
	FIFTYONE_DEGREES_STATUS_SUCCESS,
	FIFTYONE_DEGREES_STATUS_NOT_SET,
} fiftyoneDegreesStatusCode;

typedef struct fiftyone_degrees_exception_t {
	unsigned int status;
} fiftyoneDegreesException;

#define FIFTYONE_DEGREES_EXCEPTION_CLEAR \
	exception->status = FIFTYONE_DEGREES_STATUS_NOT_SET;

#define FIFTYONE_DEGREES_EXCEPTION_OKAY \
	(exception == NULL || exception->status == FIFTYONE_DEGREES_STATUS_NOT_SET)

#define FIFTYONE_DEGREES_EXCEPTION_FAILED \
	(!FIFTYONE_DEGREES_EXCEPTION_OKAY)

#define FIFTYONE_DEGREES_EXCEPTION_CREATE \
	fiftyoneDegreesException exceptionValue; \
	fiftyoneDegreesException *exception = &exceptionValue; \
	FIFTYONE_DEGREES_EXCEPTION_CLEAR

#define FIFTYONE_DEGREES_ARRAY_TYPE(t, m) \
typedef struct fiftyone_degrees_array_##t##_t { \
	uint32_t count; \
	uint32_t capacity; \
	t *items; \
	m \
} t##Array;

typedef struct fiftyone_degrees_results_base_t {
	void *dataSet;
} fiftyoneDegreesResultsBase;

typedef struct fiftyone_degrees_results_device_detection_t {
	fiftyoneDegreesResultsBase b;
} fiftyoneDegreesResultsDeviceDetection;

typedef struct fiftyone_degrees_collection_item_t {

} fiftyoneDegreesCollectionItem;

typedef struct fiftyone_degrees_list_t {

} fiftyoneDegreesList;

typedef struct fiftyone_degrees_evidence_key_value_pair_t {

} fiftyoneDegreesEvidenceKeyValuePair;

#define EVIDENCE_KEY_VALUE_MEMBERS \
	struct fiftyone_degrees_array_fiftyoneDegreesEvidenceKeyValuePair_t* pseudoEvidence;

FIFTYONE_DEGREES_ARRAY_TYPE(
	fiftyoneDegreesEvidenceKeyValuePair,
	EVIDENCE_KEY_VALUE_MEMBERS)

#define FIFTYONE_DEGREES_RESULTS_HASH_MEMBERS \
	fiftyoneDegreesResultsDeviceDetection b; \
	fiftyoneDegreesCollectionItem propertyItem; \
	fiftyoneDegreesList values; \
	fiftyoneDegreesEvidenceKeyValuePairArray* pseudoEvidence;

typedef struct fiftyone_degrees_result_hash_t {

} fiftyoneDegreesResultHash;

FIFTYONE_DEGREES_ARRAY_TYPE(
	fiftyoneDegreesResultHash,
	FIFTYONE_DEGREES_RESULTS_HASH_MEMBERS)

typedef fiftyoneDegreesResultHashArray fiftyoneDegreesResultsHash;

typedef struct fiftyone_degrees_resource_manager_t {

} fiftyoneDegreesResourceManager;

typedef struct fiftyone_degrees_header_t {
	const char* name;
	size_t nameLength;
} fiftyoneDegreesHeader;

#define FIFTYONE_DEGREES_HEADERS_MEMBERS \
	bool expectUpperPrefixedHeaders; \
	uint32_t pseudoHeadersCount;

FIFTYONE_DEGREES_ARRAY_TYPE(
	fiftyoneDegreesHeader,
	FIFTYONE_DEGREES_HEADERS_MEMBERS);

typedef fiftyoneDegreesHeaderArray fiftyoneDegreesHeaders;

typedef struct fiftyone_degrees_dataset_base_t {
	fiftyoneDegreesHeaders *uniqueHeaders;
} fiftyoneDegreesDataSetBase;

typedef struct fiftyone_degrees_dataset_device_detection_t {
	fiftyoneDegreesDataSetBase b;
} fiftyoneDegreesDataSetDeviceDetection;

typedef struct fiftyone_degrees_dataset_hash_t {
	fiftyoneDegreesDataSetDeviceDetection b;
} fiftyoneDegreesDataSetHash;

typedef enum e_fiftyone_degrees_evidence_prefix {
	FIFTYONE_DEGREES_EVIDENCE_HTTP_HEADER_STRING = 1 << 0,
	FIFTYONE_DEGREES_EVIDENCE_HTTP_HEADER_IP_ADDRESSES = 1 << 1,
	FIFTYONE_DEGREES_EVIDENCE_SERVER = 1 << 2,
	FIFTYONE_DEGREES_EVIDENCE_QUERY = 1 << 3,
	FIFTYONE_DEGREES_EVIDENCE_COOKIE = 1 << 4,
	FIFTYONE_DEGREES_EVIDENCE_IGNORE = 1 << 7,
} fiftyoneDegreesEvidencePrefix;

typedef struct fiftyone_degrees_config_base_t {
	bool freeData;
} fiftyoneDegreesConfigBase;

typedef struct fiftyone_degrees_config_device_detecton_t {
	fiftyoneDegreesConfigBase b;
	bool allowUnmatched;
} fiftyoneDegreesConfigDeviceDetection;

typedef struct fiftyone_degrees_collection_config_t {
	uint16_t concurrency;
} fiftyoneDegreesCollectionConfig;

typedef struct fiftyone_degrees_config_hash_t {
	fiftyoneDegreesConfigDeviceDetection b;
	fiftyoneDegreesCollectionConfig strings;
	fiftyoneDegreesCollectionConfig components;
	fiftyoneDegreesCollectionConfig maps;
	fiftyoneDegreesCollectionConfig properties;
	fiftyoneDegreesCollectionConfig values;
	fiftyoneDegreesCollectionConfig profiles;
	fiftyoneDegreesCollectionConfig rootNodes;
	fiftyoneDegreesCollectionConfig nodes;
	fiftyoneDegreesCollectionConfig profileOffsets;
	int32_t difference;
	int32_t drift;
	bool usePerformanceGraph;
	bool usePredictiveGraph;
} fiftyoneDegreesConfigHash;

extern fiftyoneDegreesConfigHash fiftyoneDegreesHashInMemoryConfig;

typedef struct fiftyone_degrees_property_available_t {

} fiftyoneDegreesPropertyAvailable;

FIFTYONE_DEGREES_ARRAY_TYPE(fiftyoneDegreesPropertyAvailable,)

typedef fiftyoneDegreesPropertyAvailableArray fiftyoneDegreesPropertiesAvailable;

typedef struct fiftyone_degrees_properties_required_t {
	const char **array;
	int count;
	const char *string;
	fiftyoneDegreesPropertiesAvailable *existing;
} fiftyoneDegreesPropertiesRequired;

extern fiftyoneDegreesPropertiesRequired fiftyoneDegreesPropertiesDefault;

typedef struct fiftyone_degrees_memory_reader_t {
	byte *startByte;
	byte *current;
	byte *lastByte;
	long length;
} fiftyoneDegreesMemoryReader;

fiftyoneDegreesDataSetBase* fiftyoneDegreesDataSetGet(
	fiftyoneDegreesResourceManager *manager);

void fiftyoneDegreesResultsHashFree(
	fiftyoneDegreesResultsHash* results);

fiftyoneDegreesResultsHash* fiftyoneDegreesResultsHashCreate(
	fiftyoneDegreesResourceManager *manager,
	uint32_t userAgentCapacity,
	uint32_t overridesCapacity);

void fiftyoneDegreesDataSetRelease(fiftyoneDegreesDataSetBase *dataSet);

fiftyoneDegreesEvidenceKeyValuePairArray* fiftyoneDegreesEvidenceCreate(uint32_t capacity);

fiftyoneDegreesEvidenceKeyValuePair* fiftyoneDegreesEvidenceAddString(
	fiftyoneDegreesEvidenceKeyValuePairArray *evidence,
	fiftyoneDegreesEvidencePrefix prefix,
	const char *field,
	const char *originalValue);

size_t fiftyoneDegreesResultsHashGetValuesString(
	fiftyoneDegreesResultsHash* results,
	const char *propertyName,
	char *buffer,
	size_t bufferLength,
	const char *separator,
	fiftyoneDegreesException *exception);

void fiftyoneDegreesResultsHashFromEvidence(
	fiftyoneDegreesResultsHash *results,
	fiftyoneDegreesEvidenceKeyValuePairArray *evidence,
	fiftyoneDegreesException *exception);

void fiftyoneDegreesEvidenceFree(fiftyoneDegreesEvidenceKeyValuePairArray *evidence);

void fiftyoneDegreesResultsHashFromUserAgent(
	fiftyoneDegreesResultsHash *results,
	const char* userAgent,
	size_t userAgentLength,
	fiftyoneDegreesException *exception);

fiftyoneDegreesStatusCode fiftyoneDegreesFileReadToByteArray(
	const char *fileName,
	fiftyoneDegreesMemoryReader *reader);

fiftyoneDegreesStatusCode
fiftyoneDegreesHashInitManagerFromMemory(
	fiftyoneDegreesResourceManager *manager,
	fiftyoneDegreesConfigHash *config,
	fiftyoneDegreesPropertiesRequired *properties,
	void *memory,
	long size,
	fiftyoneDegreesException *exception);

const char* fiftyoneDegreesStatusGetMessage(
	fiftyoneDegreesStatusCode status,
	const char *fileName);

#endif
