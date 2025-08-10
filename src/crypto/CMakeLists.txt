add_library(crypto
    hash.c
    ecdh.c
    kdf.c
    sign.c
    pq/kyber.c
    pq/hybrid.c
)

target_include_directories(crypto PUBLIC ${PROJECT_SOURCE_DIR}/src)
