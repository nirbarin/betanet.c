#include "origin_mirror.h"
#include "htx.h"
#include <stdlib.h>
#include <string.h>

/**
 * @brief Basic HTX Origin Mirror structure
 */
struct HTXOriginMirror {
    char *origin_domain;
    bool calibrated;
};

int htx_origin_mirror_init(const char *origin_domain, HTXOriginMirror **mirror_out) {
    if (!origin_domain || !mirror_out) {
        return HTX_ERROR_INVALID_PARAM;
    }
    
    HTXOriginMirror *mirror = calloc(1, sizeof(HTXOriginMirror));
    if (!mirror) {
        return HTX_ERROR_NO_MEMORY;
    }
    
    mirror->origin_domain = strdup(origin_domain);
    if (!mirror->origin_domain) {
        free(mirror);
        return HTX_ERROR_NO_MEMORY;
    }
    
    mirror->calibrated = false;
    
    *mirror_out = mirror;
    return 0;
}

int htx_origin_mirror_cleanup(HTXOriginMirror *mirror) {
    if (!mirror) {
        return HTX_ERROR_INVALID_PARAM;
    }
    
    if (mirror->origin_domain) {
        free(mirror->origin_domain);
    }
    
    memset(mirror, 0, sizeof(HTXOriginMirror));
    free(mirror);
    return 0;
}
