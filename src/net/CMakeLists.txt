# Add QUIC subdirectory
add_subdirectory(quic)

add_library(net
    quic.c
    tcp.c
    net_utils.c
    tls_utils.c
    conn_mgr.c
    htx/frame.c
    htx/htx.c
    htx/noise.c
    htx/origin_mirror.c
    htx/ticket.c
)

target_include_directories(net PUBLIC ${PROJECT_SOURCE_DIR}/src)

# Link against QUIC module and other dependencies
target_link_libraries(net PUBLIC quic_module OpenSSL::SSL OpenSSL::Crypto)
