#include "dac.h"

extern "C" {
void da_atlas_cache_init(const da_atlas_t *atlas) {
    (void)atlas;
}

da_status_t da_atlas_cache_insert(const da_atlas_t *atlas, unsigned long long h, da_deviceinfo_t *info) {
    (void)atlas;
    (void)h;
    (void)info;
    return DA_OK;
}

da_status_t da_atlas_cache_search(const da_atlas_t *atlas, unsigned long long h, da_deviceinfo_t **info) {
    (void)atlas;
    (void)h;
    (void)info;
    return DA_OK;
}

void da_atlas_cache_close(da_atlas_t *atlas) {
    (void)atlas;
}
}

