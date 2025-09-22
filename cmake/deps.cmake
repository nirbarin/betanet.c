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
    # Temporarily disable building tests in ngtcp2 so it doesn't register
    # a test executable named 'main' that isn't built by default.
    set(_ORIG_BUILD_TESTING "${BUILD_TESTING}")
    set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
    set(ENABLE_APPS OFF CACHE BOOL "" FORCE)
    set(ENABLE_EXAMPLES OFF CACHE BOOL "" FORCE)
    set(ENABLE_STATIC_LIB ON CACHE BOOL "" FORCE)
    set(ENABLE_SHARED_LIB OFF CACHE BOOL "" FORCE)
    set(OPENSSL_ROOT_DIR ${OPENSSL_ROOT_DIR} CACHE PATH "" FORCE)
    FetchContent_MakeAvailable(ngtcp2)

    # Restore BUILD_TESTING to previous value for this project
    if(DEFINED _ORIG_BUILD_TESTING)
      set(BUILD_TESTING ${_ORIG_BUILD_TESTING} CACHE BOOL "" FORCE)
    else()
      unset(BUILD_TESTING CACHE)
    endif()

  # Alias for compatibility
  add_library(ngtcp2 ALIAS ngtcp2_static)
  add_library(ngtcp2_crypto_ossl ALIAS ngtcp2_crypto_ossl_static)
endif()
