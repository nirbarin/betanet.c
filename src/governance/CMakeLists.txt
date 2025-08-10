add_library(governance
    quorum.c
    uptime.c
    voting.c
)

target_include_directories(governance PUBLIC ${PROJECT_SOURCE_DIR}/src)
