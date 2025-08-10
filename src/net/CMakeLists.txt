add_library(net
    quic.c
    tcp.c
    htx/frame.c
    htx/htx.c
    htx/noice.c
    htx/origin_mirror.c
    htx/ticket.c
)

target_include_directories(net PUBLIC ${PROJECT_SOURCE_DIR}/src)
