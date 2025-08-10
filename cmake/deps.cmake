include(FetchContent)

# libsodium
FetchContent_Declare(
    sodium
    GIT_REPOSITORY https://github.com/jedisct1/libsodium.git
    GIT_TAG stable
)

FetchContent_MakeAvailable(sodium)