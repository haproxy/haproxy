#include "dac.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

static char const __attribute__((unused)) rcsid[] = "$Id: dac.c, v dummy 1970/01/01 00:00:01 dcarlier Exp $";

struct da_bitset {
    unsigned long bits[8];
    size_t bit_count;
};

/*
 * Constructor/Destructor for possible globals.
 */

void
da_init()
{
}

void
da_fini()
{
}


void
da_seterrorfunc(da_errorfunc_t callback)
{
}

const char *
da_typename(da_type_t fieldtype)
{
   return "none";
}

char *
da_getdataversion(da_atlas_t *atlas)
{
    return "dummy library version 1.0";
}

time_t
da_getdatacreation(da_atlas_t *atlas)
{
    return time(NULL);
}

int
da_getdatarevision(da_atlas_t *atlas)
{
    return 1;
}

da_status_t
da_atlas_compile(void *ctx, da_read_fn readfn, da_setpos_fn rewind, void **ptr, size_t *size)
{
    return DA_OK;
}

da_status_t
da_atlas_open(da_atlas_t *atlas, da_property_decl_t *extraprops, const void *ptr, size_t len)
{
    ptr = malloc(len);
    return ptr ? DA_OK : DA_NOMEM;
}

void
da_atlas_close(da_atlas_t *atlas)
{
}

da_evidence_id_t
da_atlas_clientprop_evidence_id(const da_atlas_t *atlas)
{
    return (da_evidence_id_t)2;
}

da_evidence_id_t
da_atlas_accept_language_evidence_id(const da_atlas_t *atlas)
{
    return (da_evidence_id_t)3;
}

da_evidence_id_t
da_atlas_header_evidence_id(const da_atlas_t *atlas, const char *evidence_name)
{
    return (da_evidence_id_t)1;
}

da_status_t
da_atlas_getproptype(const da_atlas_t *atlas, da_propid_t propid, da_type_t *type)
{
    *type = DA_TYPE_BOOLEAN;
    return DA_OK;
}

da_status_t
da_atlas_getpropname(const da_atlas_t *atlas, da_propid_t propid, const char **name)
{
    *name = "isRobot";
    return DA_OK;
}

da_status_t
da_atlas_getpropid(const da_atlas_t *atlas, const char *propname, da_propid_t *property)
{
    *property = (da_propid_t)1;
    return DA_OK;
}

size_t
da_atlas_getpropcount(const da_atlas_t *atlas)
{
    return 1;
}

void
da_atlas_setconfig(da_atlas_t *atlas, da_config_t *config)
{
}

da_status_t
da_searchv(const da_atlas_t *atlas, da_deviceinfo_t *result, da_evidence_t *evidence, size_t count)
{
    memset(result, 0, sizeof(*result));
    result->propcount = count;
    return DA_OK;
}

da_status_t
da_search(const da_atlas_t *atlas, da_deviceinfo_t *result, ...)
{
    da_evidence_t vec[4]; /* XXX: this will have to grow if more evidence is supported. */
    size_t i;
    va_list args;
    va_start(args, result);
    for (i = 0; i < sizeof vec / sizeof vec[0];) {
        vec[i].key = va_arg(args, da_evidence_id_t);
        if (vec[i].key == 0)
            break;
        vec[i++].value = va_arg(args, char *);
    }
    va_end(args);
    return da_searchv(atlas, result, vec, i);
}

/*
 * Search-result centric functions.
 */
size_t
da_getpropcount(const da_deviceinfo_t *info)
{
    return info->propcount;
}

da_status_t
da_getfirstprop(const da_deviceinfo_t *info, da_propid_t **propid)
{
    if (info->propcount == 0)
        return DA_NOMORE;
    *propid = &info->proplist[0];
    return DA_OK;
}

da_status_t
da_getnextprop(const da_deviceinfo_t *info, da_propid_t **propid)
{
    if (*propid - info->proplist >= info->propcount - 1)
        return DA_NOMORE;
    ++*propid;
    return DA_OK;
}

void
da_close(da_deviceinfo_t *sr)
{
}

da_status_t
da_getpropname(const da_deviceinfo_t *info, da_propid_t propid, const char **name)
{
    *name = "isRobot";
    return DA_OK;
}

da_status_t
da_getproptype(const da_deviceinfo_t *info, da_propid_t propid, da_type_t *type)
{
    *type = DA_TYPE_BOOLEAN;
    return DA_OK;
}

da_status_t
da_getpropinteger(const da_deviceinfo_t *info, da_propid_t property, long *vp)
{
     *vp = -1;
    return DA_OK;
}

da_status_t
da_getpropstring(const da_deviceinfo_t *info, da_propid_t property, const char **vp)
{
    *vp = NULL;
    return DA_OK;
}

da_status_t
da_getpropboolean(const da_deviceinfo_t *info, da_propid_t property, bool *vp)
{
    *vp = true;
    return DA_OK;
}

const char *
da_get_property_name(const da_atlas_t *atlas, da_propid_t property)
{
    return "isRobot";
}
