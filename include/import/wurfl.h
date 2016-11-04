#ifndef _IMPORT_WURFL_H
#define _IMPORT_WURFL_H

#include <wurfl/wurfl.h>

int ha_wurfl_init(void);
void ha_wurfl_deinit(void);

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

#endif
