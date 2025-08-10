add_library(naming
    id.c
    ledger.c
    quorum.c
)

target_include_directories(naming PUBLIC ${PROJECT_SOURCE_DIR}/src)
