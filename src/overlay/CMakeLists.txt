add_library(overlay
    bitswap.c
    discovery.c
    libp2p.c
    peer.c
    pow.c
)

target_include_directories(overlay PUBLIC ${PROJECT_SOURCE_DIR}/src)
