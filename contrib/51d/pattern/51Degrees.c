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
#include "51Degrees.h"
#include <stdlib.h>

int32_t fiftyoneDegreesGetSignatureRank(fiftyoneDegreesWorkset *ws) {
    return 0;
}

const char* fiftyoneDegreesGetPropertyName(
	const fiftyoneDegreesDataSet *dataSet,
	const fiftyoneDegreesProperty *property) {
    return "dummy-property";
}

int32_t fiftyoneDegreesSetValues(
	fiftyoneDegreesWorkset *ws,
	int32_t requiredPropertyIndex) {
    return 0;
}

const char* fiftyoneDegreesGetValueName(
	const fiftyoneDegreesDataSet *dataSet,
	const fiftyoneDegreesValue *value) {
    return "dummy-value";
}

static fiftyoneDegreesDataSet dummyDataSet = {
    0,
    (fiftyoneDegreesHttpHeader*)NULL,
    0,
    (const fiftyoneDegreesProperty**)NULL
};

static fiftyoneDegreesWorkset dummyWorkset = {
	&dummyDataSet,
	0,
	(fiftyoneDegreesHttpHeaderWorkset*)NULL,
    EXACT,
    0,
    (const fiftyoneDegreesValue **)NULL
};

fiftyoneDegreesWorkset *fiftyoneDegreesWorksetPoolGet(
	fiftyoneDegreesWorksetPool *pool) {
    return &dummyWorkset;
}

void fiftyoneDegreesWorksetPoolRelease(
    fiftyoneDegreesWorksetPool *pool,
    fiftyoneDegreesWorkset *ws) {
    return;
}

void fiftyoneDegreesMatchForHttpHeaders(fiftyoneDegreesWorkset *ws) {
    return;
}

void fiftyoneDegreesMatch(
	fiftyoneDegreesWorkset *ws,
	const char* userAgent) {
    return;
}

fiftyoneDegreesDataSetInitStatus fiftyoneDegreesInitWithPropertyArray(
	const char *fileName,
	fiftyoneDegreesDataSet *dataSet,
	const char** properties,
	int32_t count) {
    return DATA_SET_INIT_STATUS_SUCCESS;
}

static fiftyoneDegreesWorksetPool dummyWorksetPool;

fiftyoneDegreesWorksetPool *fiftyoneDegreesWorksetPoolCreate(
	fiftyoneDegreesDataSet *dataSet,
	fiftyoneDegreesResultsetCache *cache,
	int32_t size) {
    return &dummyWorksetPool;
}

void fiftyoneDegreesWorksetPoolFree(
	const fiftyoneDegreesWorksetPool *pool) {
    return;
}

void fiftyoneDegreesDataSetFree(const fiftyoneDegreesDataSet *dataSet) {
    return;
}

static fiftyoneDegreesAsciiString dummyAsciiString = {0, 0};

const fiftyoneDegreesAsciiString* fiftyoneDegreesGetString(
	const fiftyoneDegreesDataSet *dataSet,
	int32_t offset) {
		return &dummyAsciiString;
}