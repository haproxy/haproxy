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

#ifndef FIFTYONEDEGREES_H_TRIE_INCLUDED
#define FIFTYONEDEGREES_H_TRIE_INCLUDED
#endif

#ifndef FIFTYONEDEGREES_DUMMY_LIB
#define FIFTYONEDEGREES_DUMMY_LIB
#endif

#include <stdint.h>

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

typedef struct fiftyoneDegrees_integers_t {
	int32_t *firstElement;
	unsigned int count;
	int freeMemory;
} fiftyoneDegreesIntegers;

typedef struct fiftyoneDegrees_dataset_t {
    fiftyoneDegreesIntegers uniqueHttpHeaders;
} fiftyoneDegreesDataSet;

typedef struct fiftyoneDegrees_active_dataset_t {

} fiftyoneDegreesActiveDataSet;

typedef struct fiftyoneDegrees_device_offset_t {
    int httpHeaderOffset;
    int deviceOffset;
    char *userAgent;
} fiftyoneDegreesDeviceOffset;

typedef struct fiftyoneDegrees_device_offsets_t {
    int size;
	fiftyoneDegreesDeviceOffset *firstOffset;
	fiftyoneDegreesActiveDataSet *active;
} fiftyoneDegreesDeviceOffsets;

int fiftyoneDegreesGetDeviceOffset(
	fiftyoneDegreesDataSet *dataSet,
	const char *userAgent);

const char** fiftyoneDegreesGetRequiredPropertiesNames(
	fiftyoneDegreesDataSet *dataSet);

int fiftyoneDegreesGetRequiredPropertiesCount(
	fiftyoneDegreesDataSet *dataSet);

int fiftyoneDegreesGetValueFromOffsets(
	fiftyoneDegreesDataSet *dataSet,
	fiftyoneDegreesDeviceOffsets* deviceOffsets,
	int requiredPropertyIndex,
	char* values,
	int size);

fiftyoneDegreesDeviceOffsets* fiftyoneDegreesCreateDeviceOffsets(
	fiftyoneDegreesDataSet *dataSet);

void fiftyoneDegreesFreeDeviceOffsets(
	fiftyoneDegreesDeviceOffsets* offsets);

int fiftyoneDegreesGetHttpHeaderCount(
	fiftyoneDegreesDataSet *dataSet);

int fiftyoneDegreesGetHttpHeaderNameOffset(
	fiftyoneDegreesDataSet *dataSet,
	int httpHeaderIndex);

const char* fiftyoneDegreesGetHttpHeaderNamePointer(
	fiftyoneDegreesDataSet *dataSet,
	int httpHeaderIndex);

fiftyoneDegreesDataSetInitStatus fiftyoneDegreesInitWithPropertyArray(
	const char* fileName,
	fiftyoneDegreesDataSet *dataSet,
	const char** properties,
	int propertyCount);

void fiftyoneDegreesDataSetFree(fiftyoneDegreesDataSet *dataSet);

#endif