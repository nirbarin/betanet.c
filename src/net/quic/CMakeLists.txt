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
    ${ngtcp2_SOURCE_DIR}/lib/includes    # For ngtcp2.h
    ${ngtcp2_SOURCE_DIR}/crypto/includes  # For ngtcp2_crypto.h
)

# Link against dependencies
target_link_libraries(quic_module PUBLIC ngtcp2 ngtcp2_crypto_ossl OpenSSL::SSL OpenSSL::Crypto)