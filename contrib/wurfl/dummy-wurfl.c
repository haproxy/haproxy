/*
 * InFuze C API - HAPROXY Dummy library version of include
 *
 * Author : Paul Stephen Borile, Mon Apr 8, 2019
 * Copyright (c) ScientiaMobile, Inc.
 * http://www.scientiamobile.com
 *
 * This is a dummy implementation of the wurfl C API that builds and runs
 * like the normal API simply without returning device detection data
 *
 *
 */

#include "wurfl/wurfl.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

const char *wurfl_get_api_version(void)
{
 return "1.11.2.100"; // 100 indicates the dummy
}

wurfl_handle wurfl_create(void)
{
  return (void*) 0xbeffa;
}

void wurfl_destroy(wurfl_handle handle)
{
  return;
}

wurfl_error wurfl_set_root(wurfl_handle hwurfl, const char* root)
{
  return WURFL_OK;
}
wurfl_error wurfl_add_patch(wurfl_handle hwurfl, const char *patch)
{
  return WURFL_OK;
}

wurfl_error wurfl_add_requested_capability(wurfl_handle hwurfl, const char *requested_capability)
{
  return WURFL_OK;
}

const char *wurfl_get_error_message(wurfl_handle hwurfl)
{
  return "wurfl dummy library error message";
}

int wurfl_has_virtual_capability(wurfl_handle hwurfl, const char *virtual_capability)
{
  return 0;
}

wurfl_error wurfl_set_cache_provider(wurfl_handle hwurfl, wurfl_cache_provider cache_provider, const char *config)
{
  return WURFL_OK;
}

wurfl_error wurfl_load(wurfl_handle hwurfl)
{
  return WURFL_OK;
}

wurfl_device_handle wurfl_lookup(wurfl_handle hwurfl, wurfl_header_retrieve_callback header_retrieve_callback, const void *header_retrieve_callback_data)
{
  // call callback, on a probably existing header
  const char *hvalue = header_retrieve_callback("User-Agent", header_retrieve_callback_data);
  // and on a non existing one
  hvalue = header_retrieve_callback("Non-Existing-Header", header_retrieve_callback_data);
  (void)hvalue;
  return (void *) 0xdeffa;
}

const char *wurfl_device_get_capability(wurfl_device_handle hwurfldevice, const char *capability)
{
  return "dummy_cap_val";
}

const char *wurfl_device_get_virtual_capability(wurfl_device_handle hwurfldevice, const char *capability)
{
  return "dummy_vcap_val";
}

void wurfl_device_destroy(wurfl_device_handle handle)
{
  return;
}

const char *wurfl_device_get_id(wurfl_device_handle hwurfldevice)
{
  return "generic_dummy_device";
}

const char *wurfl_device_get_root_id(wurfl_device_handle hwurfldevice)
{
  return "generic_dummy_device";
}

const char *wurfl_device_get_original_useragent(wurfl_device_handle hwurfldevice)
{
  return "original_useragent";
}
const char *wurfl_device_get_normalized_useragent(wurfl_device_handle hwurfldevice)
{
  return "normalized_useragent";
}
int wurfl_device_is_actual_device_root(wurfl_device_handle hwurfldevice)
{
  return 1;
}

const char *wurfl_get_wurfl_info(wurfl_handle hwurfl)
{
  return "dummy wurfl info";
}

const char *wurfl_get_last_load_time_as_string(wurfl_handle hwurfl)
{
  return "dummy wurfl last load time";
}

#pragma GCC diagnostic pop
