#ifndef MOBI_DA_DAC_HAPROXY_H
#define MOBI_DA_DAC_HAPROXY_H
#ifdef USE_DEVICEATLAS

#include <types/global.h>
#include <dac.h>

int init_deviceatlas(void);
void deinit_deviceatlas(void);
#endif
#endif
