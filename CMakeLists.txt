cmake_minimum_required(VERSION 3.16)
project(betanet C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Enable testing
enable_testing()

# include deps
include(cmake/deps.cmake)

# include global headers
include_directories(${PROJECT_SOURCE_DIR}/src)

# add subdirectories for each module
add_subdirectory(src/crypto)
add_subdirectory(src/net)
add_subdirectory(src/scion)
add_subdirectory(src/overlay)
add_subdirectory(src/privacy)
add_subdirectory(src/naming)
add_subdirectory(src/payment)
add_subdirectory(src/governance)

# add tests
add_subdirectory(tests)

# main executable
add_executable(betanet src/main.c src/config.h)

# link all module libraries to the main binary
target_link_libraries(betanet
    PRIVATE
    crypto
    net
    scion
    overlay
    privacy
    naming
    payment
    governance
)
