# Tests CMakeLists.txt
cmake_minimum_required(VERSION 3.16)

# Enable CTest for running tests
enable_testing()

# Add crypto test executables
add_executable(test_hash crypto/test_hash.c)
target_link_libraries(test_hash PRIVATE crypto)

add_executable(test_ecdh crypto/test_ecdh.c)
target_link_libraries(test_ecdh PRIVATE crypto)

add_executable(test_kdf crypto/test_kdf.c)
target_link_libraries(test_kdf PRIVATE crypto)

add_executable(test_sign crypto/test_sign.c)
target_link_libraries(test_sign PRIVATE crypto)

# Add tests to CTest
add_test(NAME test_hash COMMAND test_hash)
add_test(NAME test_ecdh COMMAND test_ecdh)
add_test(NAME test_kdf COMMAND test_kdf)
add_test(NAME test_sign COMMAND test_sign)
