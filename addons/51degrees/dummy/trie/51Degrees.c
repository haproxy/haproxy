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

int fiftyoneDegreesGetDeviceOffset(
	fiftyoneDegreesDataSet *dataSet,
	const char *userAgent) {
    return 0;
}

const char** fiftyoneDegreesGetRequiredPropertiesNames(
	fiftyoneDegreesDataSet *dataSet) {
    return NULL;
}

int fiftyoneDegreesGetRequiredPropertiesCount(
	fiftyoneDegreesDataSet *dataSet) {
    return 0;
}

int fiftyoneDegreesGetValueFromOffsets(
	fiftyoneDegreesDataSet *dataSet,
	fiftyoneDegreesDeviceOffsets* deviceOffsets,
	int requiredPropertyIndex,
	char* values,
	int size) {
    return 0;
}

static fiftyoneDegreesDeviceOffset dummyOffset = { 0, 0, "dummy-user-agent" };

static fiftyoneDegreesDeviceOffsets dummyOffsets = { 1, &dummyOffset, NULL };

fiftyoneDegreesDeviceOffsets* fiftyoneDegreesCreateDeviceOffsets(
	fiftyoneDegreesDataSet *dataSet) {
    return &dummyOffsets;
}

void fiftyoneDegreesFreeDeviceOffsets(
	fiftyoneDegreesDeviceOffsets* offsets) {
    return;
}

int fiftyoneDegreesGetHttpHeaderCount(
	fiftyoneDegreesDataSet *dataSet) {
    return 0;
}

int fiftyoneDegreesGetHttpHeaderNameOffset(
	fiftyoneDegreesDataSet *dataSet,
	int httpHeaderIndex) {
    return 0;
}

const char* fiftyoneDegreesGetHttpHeaderNamePointer(
	fiftyoneDegreesDataSet *dataSet,
	int httpHeaderIndex) {
    return "dummy-header-name";
}

fiftyoneDegreesDataSetInitStatus fiftyoneDegreesInitWithPropertyArray(
	const char* fileName,
	fiftyoneDegreesDataSet *dataSet,
	const char** properties,
	int propertyCount) {
    return DATA_SET_INIT_STATUS_SUCCESS;
}

void fiftyoneDegreesDataSetFree(fiftyoneDegreesDataSet *dataSet) {
    return;
}