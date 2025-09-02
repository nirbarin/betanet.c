# Tests CMakeLists.txt
cmake_minimum_required(VERSION 3.16)

# Enable CTest for running tests
enable_testing()

# Define test targets
add_test(NAME test_hash COMMAND test_hash)
add_test(NAME test_ecdh COMMAND test_ecdh)
add_test(NAME test_kdf COMMAND test_kdf)
add_test(NAME test_sign COMMAND test_sign)
add_test(NAME test_registry COMMAND test_registry)
add_test(NAME test_tcp COMMAND test_tcp)
add_test(NAME test_quic COMMAND test_quic)
add_test(NAME test_net_utils COMMAND test_net_utils)
add_test(NAME test_tls_utils COMMAND test_tls_utils)
add_test(NAME test_conn_mgr COMMAND test_conn_mgr)
add_test(NAME test_htx COMMAND test_htx)

# Add crypto test executables
add_executable(test_hash crypto/test_hash.c)
target_link_libraries(test_hash PRIVATE crypto)

add_executable(test_ecdh crypto/test_ecdh.c)
target_link_libraries(test_ecdh PRIVATE crypto)

add_executable(test_kdf crypto/test_kdf.c)
target_link_libraries(test_kdf PRIVATE crypto)

add_executable(test_sign crypto/test_sign.c)
target_link_libraries(test_sign PRIVATE crypto)

add_executable(test_registry crypto/test_registry.c)
target_link_libraries(test_registry PRIVATE crypto)

# Add network test executables
add_executable(test_tcp net/test_tcp.c)
target_link_libraries(test_tcp PRIVATE net Threads::Threads)

add_executable(test_quic net/test_quic.c)
target_link_libraries(test_quic PRIVATE net Threads::Threads)

add_executable(test_net_utils net/test_net_utils.c)
target_link_libraries(test_net_utils PRIVATE net Threads::Threads)

add_executable(test_htx net/test_htx.c)
target_link_libraries(test_htx PRIVATE net Threads::Threads)

add_executable(test_tls_utils net/test_tls_utils.c)
target_link_libraries(test_tls_utils PRIVATE net Threads::Threads)
target_compile_definitions(test_tls_utils PRIVATE
    CMAKE_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
)

add_executable(test_conn_mgr net/test_conn_mgr.c)
target_link_libraries(test_conn_mgr PRIVATE net Threads::Threads)

# Generate certificates for TLS tests
add_custom_command(
    OUTPUT "${CMAKE_CURRENT_SOURCE_DIR}/net/ca.crt"
           "${CMAKE_CURRENT_SOURCE_DIR}/net/server.crt"
           "${CMAKE_CURRENT_SOURCE_DIR}/net/client.crt"
    COMMAND bash "${CMAKE_CURRENT_SOURCE_DIR}/net/generate_certs.sh"
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/net/generate_certs.sh"
    COMMENT "Generating TLS certificates for tests"
    VERBATIM
)
add_custom_target(generate_test_certs 
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/net/ca.crt"
            "${CMAKE_CURRENT_SOURCE_DIR}/net/server.crt"
            "${CMAKE_CURRENT_SOURCE_DIR}/net/client.crt"
)
add_dependencies(test_tcp generate_test_certs)
add_dependencies(test_quic generate_test_certs)
add_dependencies(test_tls_utils generate_test_certs)
add_dependencies(test_conn_mgr generate_test_certs)
