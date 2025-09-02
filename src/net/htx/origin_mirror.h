#ifndef BETANET_NET_HTX_ORIGIN_MIRROR_H_
#define BETANET_NET_HTX_ORIGIN_MIRROR_H_

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/**
 * @brief HTX Origin Mirroring Implementation
 * 
 * Implements TLS fingerprint mirroring to make HTX connections appear
 * as legitimate HTTPS traffic to the specified origin domain.
 */

/** Forward declaration for opaque type */
typedef struct HTXOriginMirror HTXOriginMirror;

/**
 * @brief Initialize origin mirroring
 *
 * Sets up TLS fingerprint mirroring for the specified origin domain.
 *
 * @param origin_domain Domain to mirror TLS fingerprint from
 * @param mirror_out Pointer to store created mirror state
 *
 * @return 0 on success, negative value on error
 *         - HTX_ERROR_INVALID_PARAM: Invalid parameters
 *
 * @example
 * HTXOriginMirror *mirror;
 * int result = htx_origin_mirror_init("example.com", &mirror);
 */
int htx_origin_mirror_init(const char *origin_domain, HTXOriginMirror **mirror_out);

/**
 * @brief Clean up origin mirror state
 *
 * Cleans up and frees origin mirror resources.
 *
 * @param mirror Origin mirror to clean up
 *
 * @return 0 on success, negative value on error
 */
int htx_origin_mirror_cleanup(HTXOriginMirror *mirror);

#endif /* BETANET_NET_HTX_ORIGIN_MIRROR_H_ */
