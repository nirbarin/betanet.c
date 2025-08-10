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