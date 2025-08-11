include(FetchContent)

# libsodium
FetchContent_Declare(
    sodium
    GIT_REPOSITORY https://github.com/jedisct1/libsodium.git
    GIT_TAG stable
)

FetchContent_MakeAvailable(sodium)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Add pthread support
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

# ngtcp2 (QUIC v1 + HTTP/3)
# Pure C implementation of QUIC protocol (RFC9000)
FetchContent_Declare(
    ngtcp2
    GIT_REPOSITORY https://github.com/ngtcp2/ngtcp2.git
    GIT_TAG v1.14.0
)

FetchContent_GetProperties(ngtcp2)
if(NOT ngtcp2_POPULATED)
  FetchContent_Populate(ngtcp2)
  
  # Create a library target for ngtcp2
  add_library(ngtcp2 STATIC IMPORTED)
  
  # Options for building ngtcp2
  set(ENABLE_APPS OFF CACHE BOOL "")
  set(ENABLE_EXAMPLES OFF CACHE BOOL "")
  set(ENABLE_STATIC_LIB ON CACHE BOOL "")
  set(ENABLE_SHARED_LIB OFF CACHE BOOL "")
  
  # Build ngtcp2 library
  execute_process(
    COMMAND mkdir -p build
    WORKING_DIRECTORY ${ngtcp2_SOURCE_DIR}
  )
  execute_process(
    COMMAND cmake -DCMAKE_BUILD_TYPE=Release 
                  -DENABLE_APPS=${ENABLE_APPS}
                  -DENABLE_EXAMPLES=${ENABLE_EXAMPLES}
                  -DENABLE_STATIC_LIB=${ENABLE_STATIC_LIB}
                  -DENABLE_SHARED_LIB=${ENABLE_SHARED_LIB}
                  -DOPENSSL_ROOT_DIR=${OPENSSL_ROOT_DIR}
                  ..
    WORKING_DIRECTORY ${ngtcp2_SOURCE_DIR}/build
  )
  execute_process(
    COMMAND cmake --build .
    WORKING_DIRECTORY ${ngtcp2_SOURCE_DIR}/build
  )
  
  # Set the include directories
  target_include_directories(ngtcp2 INTERFACE 
    ${ngtcp2_SOURCE_DIR}/lib/includes
  )
  
  # Set the library location
  set_target_properties(ngtcp2 PROPERTIES
    IMPORTED_LOCATION "${ngtcp2_SOURCE_DIR}/build/lib/libngtcp2.a"
  )
  
  # Create a target for ngtcp2_crypto_ossl
  add_library(ngtcp2_crypto_ossl STATIC IMPORTED)
  set_target_properties(ngtcp2_crypto_ossl PROPERTIES
    IMPORTED_LOCATION "${ngtcp2_SOURCE_DIR}/build/crypto/ossl/libngtcp2_crypto_ossl.a"
  )
  target_include_directories(ngtcp2_crypto_ossl INTERFACE 
    ${ngtcp2_SOURCE_DIR}/crypto/includes
  )
  
  # Link ngtcp2_crypto_ossl with OpenSSL
  target_link_libraries(ngtcp2_crypto_ossl INTERFACE OpenSSL::SSL OpenSSL::Crypto)
endif()
