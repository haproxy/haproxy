/* *********************************************************************
 * This Source Code Form is copyright of 51Degrees Mobile Experts Limited.
 * Copyright 2019 51Degrees Mobile Experts Limited, 5 Charlotte Close,
 * Caversham, Reading, Berkshire, United Kingdom RG4 7BY
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0.
 *
 * If a copy of the MPL was not distributed with this file, You can obtain
 * one at http://mozilla.org/MPL/2.0/.
 *
 * This Source Code Form is "Incompatible With Secondary Licenses", as
 * defined by the Mozilla Public License, v. 2.0.
 * *********************************************************************/

/* *********************************************************************
 * Dummy library for HAProxy. This does not function, and is designed
 * solely for HAProxy testing purposes.
 * *********************************************************************/
#ifndef FIFTYONEDEGREES_H_INCLUDED
#define FIFTYONEDEGREES_H_INCLUDED

#ifndef FIFTYONEDEGREES_H_PATTERN_INCLUDED
#define FIFTYONEDEGREES_H_PATTERN_INCLUDED
#endif

#ifndef FIFTYONEDEGREES_DUMMY_LIB
#define FIFTYONEDEGREES_DUMMY_LIB
#endif

#include <stdint.h>

typedef enum e_fiftyoneDegrees_MatchMethod {
	NONE,
	EXACT,
	NUMERIC,
	NEAREST,
	CLOSEST
} fiftyoneDegreesMatchMethod;

typedef enum e_fiftyoneDegrees_DataSetInitStatus {
	DATA_SET_INIT_STATUS_SUCCESS,
	DATA_SET_INIT_STATUS_INSUFFICIENT_MEMORY,
	DATA_SET_INIT_STATUS_CORRUPT_DATA,
	DATA_SET_INIT_STATUS_INCORRECT_VERSION,
	DATA_SET_INIT_STATUS_FILE_NOT_FOUND,
	DATA_SET_INIT_STATUS_NOT_SET,
	DATA_SET_INIT_STATUS_POINTER_OUT_OF_BOUNDS,
	DATA_SET_INIT_STATUS_NULL_POINTER
} fiftyoneDegreesDataSetInitStatus;

typedef struct fiftyoneDegrees_ascii_string_t {
	const int16_t length;
	const char firstByte;
} fiftyoneDegreesAsciiString;

typedef struct fiftyoneDegrees_dataset_header_t {
} fiftyoneDegreesDataSetHeader;

typedef struct fiftyoneDegrees_workset_pool_t {
} fiftyoneDegreesWorksetPool;

typedef struct fiftyoneDegrees_property_t {
} fiftyoneDegreesProperty;

typedef struct fiftyoneDegrees_value_t {
} fiftyoneDegreesValue;

typedef struct fiftyoneDegrees_resultset_cache_t {
} fiftyoneDegreesResultsetCache;

typedef struct fiftyoneDegrees_http_header_t {
	int32_t headerNameOffset;
	const char *headerName;
} fiftyoneDegreesHttpHeader;

typedef struct fiftyoneDegrees_http_header_workset_t {
	fiftyoneDegreesHttpHeader *header;
	const char *headerValue;
	int headerValueLength;
} fiftyoneDegreesHttpHeaderWorkset;


typedef struct fiftyoneDegrees_dataset_t {
    int32_t httpHeadersCount;
    fiftyoneDegreesHttpHeader *httpHeaders;
    int32_t requiredPropertyCount;
    const fiftyoneDegreesProperty **requiredProperties;
} fiftyoneDegreesDataSet;

typedef struct fiftyoneDegrees_workset_t {
    fiftyoneDegreesDataSet *dataSet;
	int32_t importantHeadersCount;
	fiftyoneDegreesHttpHeaderWorkset *importantHeaders;
    fiftyoneDegreesMatchMethod method;
    int32_t difference;
    const fiftyoneDegreesValue **values;
} fiftyoneDegreesWorkset;

int32_t fiftyoneDegreesGetSignatureRank(fiftyoneDegreesWorkset *ws);

const char* fiftyoneDegreesGetPropertyName(
	const fiftyoneDegreesDataSet *dataSet,
	const fiftyoneDegreesProperty *property);

int32_t fiftyoneDegreesSetValues(
	fiftyoneDegreesWorkset *ws,
	int32_t requiredPropertyIndex);

const char* fiftyoneDegreesGetValueName(
	const fiftyoneDegreesDataSet *dataSet,
	const fiftyoneDegreesValue *value);

fiftyoneDegreesWorkset *fiftyoneDegreesWorksetPoolGet(
	fiftyoneDegreesWorksetPool *pool);

void fiftyoneDegreesWorksetPoolRelease(
    fiftyoneDegreesWorksetPool *pool,
    fiftyoneDegreesWorkset *ws);

void fiftyoneDegreesMatchForHttpHeaders(fiftyoneDegreesWorkset *ws);

void fiftyoneDegreesMatch(
	fiftyoneDegreesWorkset *ws,
	const char* userAgent);

fiftyoneDegreesDataSetInitStatus fiftyoneDegreesInitWithPropertyArray(
	const char *fileName,
	fiftyoneDegreesDataSet *dataSet,
	const char** properties,
	int32_t count);

fiftyoneDegreesWorksetPool *fiftyoneDegreesWorksetPoolCreate(
	fiftyoneDegreesDataSet *dataSet,
	fiftyoneDegreesResultsetCache *cache,
	int32_t size);

void fiftyoneDegreesWorksetPoolFree(
	const fiftyoneDegreesWorksetPool *pool);

void fiftyoneDegreesDataSetFree(const fiftyoneDegreesDataSet *dataSet);

const fiftyoneDegreesAsciiString* fiftyoneDegreesGetString(
	const fiftyoneDegreesDataSet *dataSet,
	int32_t offset);

#endif