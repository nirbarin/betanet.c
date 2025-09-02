# Add QUIC subdirectory (temporarily disabled due to dependency issues)
# add_subdirectory(quic)

add_library(net
    # quic.c (temporarily disabled)
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

# Link against dependencies (QUIC module temporarily removed)
target_link_libraries(net PUBLIC OpenSSL::SSL OpenSSL::Crypto pthread)
