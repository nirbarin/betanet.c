add_library(privacy
  mixnet.c
  selection.c
  trust.c
)

target_include_directories(privacy PUBLIC ${PROJECT_SOURCE_DIR}/src)
