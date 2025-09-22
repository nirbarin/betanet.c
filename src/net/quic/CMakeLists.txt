# QUIC module CMakeLists.txt
add_library(quic_module
    config.c
    conn.c
    stream.c
    masque.c
)

# Set include directories
target_include_directories(quic_module PUBLIC 
    ${CMAKE_CURRENT_SOURCE_DIR}  # For quic.h
    ${PROJECT_SOURCE_DIR}/src    # For other headers
    ${PROJECT_BINARY_DIR}/_deps/ngtcp2-src/lib/includes    # For ngtcp2.h
    ${PROJECT_BINARY_DIR}/_deps/ngtcp2-src/crypto/includes  # For ngtcp2_crypto.h
)

# Link against dependencies
target_link_libraries(quic_module PUBLIC ngtcp2_static ngtcp2_crypto_ossl_static OpenSSL::SSL OpenSSL::Crypto)