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
#include "hash.h"
#include "fiftyone.h"

static fiftyoneDegreesHeaders dummyHeaders = { };
static fiftyoneDegreesDataSetBase dummyDataSet = { &dummyHeaders };

fiftyoneDegreesConfigHash fiftyoneDegreesHashInMemoryConfig;
fiftyoneDegreesPropertiesRequired fiftyoneDegreesPropertiesDefault;

fiftyoneDegreesDataSetBase* fiftyoneDegreesDataSetGet(
	fiftyoneDegreesResourceManager *manager) {
	return &dummyDataSet;
}

void fiftyoneDegreesResultsHashFree(
	fiftyoneDegreesResultsHash* results) {
	return;
}

static fiftyoneDegreesResultsHash dummyResults = { };

fiftyoneDegreesResultsHash* fiftyoneDegreesResultsHashCreate(
	fiftyoneDegreesResourceManager *manager,
	uint32_t userAgentCapacity,
	uint32_t overridesCapacity) {
	return &dummyResults;
}

void fiftyoneDegreesDataSetRelease(fiftyoneDegreesDataSetBase *dataSet) {
	return;
}

static fiftyoneDegreesEvidenceKeyValuePairArray dummyEvidence = { };

fiftyoneDegreesEvidenceKeyValuePairArray*
fiftyoneDegreesEvidenceCreate(uint32_t capacity) {
	return &dummyEvidence;
}

fiftyoneDegreesEvidenceKeyValuePair* fiftyoneDegreesEvidenceAddString(
	fiftyoneDegreesEvidenceKeyValuePairArray *evidence,
	fiftyoneDegreesEvidencePrefix prefix,
	const char *field,
	const char *originalValue) {
	return NULL;
}

size_t fiftyoneDegreesResultsHashGetValuesString(
	fiftyoneDegreesResultsHash* results,
	const char *propertyName,
	char *buffer,
	size_t bufferLength,
	const char *separator,
	fiftyoneDegreesException *exception) {
	return 0;
}

void fiftyoneDegreesResultsHashFromEvidence(
	fiftyoneDegreesResultsHash *results,
	fiftyoneDegreesEvidenceKeyValuePairArray *evidence,
	fiftyoneDegreesException *exception) {
	return;
}

void fiftyoneDegreesEvidenceFree(fiftyoneDegreesEvidenceKeyValuePairArray *evidence) {
	return;
}

void fiftyoneDegreesResultsHashFromUserAgent(
	fiftyoneDegreesResultsHash *results,
	const char* userAgent,
	size_t userAgentLength,
	fiftyoneDegreesException *exception) {
	return;
}

fiftyoneDegreesStatusCode fiftyoneDegreesFileReadToByteArray(
	const char *fileName,
	fiftyoneDegreesMemoryReader *reader) {
	return FIFTYONE_DEGREES_STATUS_SUCCESS;
}

fiftyoneDegreesStatusCode
fiftyoneDegreesHashInitManagerFromMemory(
	fiftyoneDegreesResourceManager *manager,
	fiftyoneDegreesConfigHash *config,
	fiftyoneDegreesPropertiesRequired *properties,
	void *memory,
	long size,
	fiftyoneDegreesException *exception) {
	return FIFTYONE_DEGREES_STATUS_SUCCESS;
}

const char* fiftyoneDegreesStatusGetMessage(
	fiftyoneDegreesStatusCode status,
	const char *fileName) {
	return NULL;
}
