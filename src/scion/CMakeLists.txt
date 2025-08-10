add_library(scion
  transtion.c
  path/path.c
  path/maintenance.c
)

target_include_directories(scion PUBLIC ${PROJECT_SOURCE_DIR}/src)
