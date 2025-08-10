# Tests CMakeLists.txt
cmake_minimum_required(VERSION 3.16)

# Enable CTest for running tests
enable_testing()

# Add crypto test executable
add_executable(test_hash crypto/test_hash.c)
target_link_libraries(test_hash PRIVATE crypto)

# Add test to CTest
add_test(NAME test_hash COMMAND test_hash)