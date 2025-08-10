add_library(payment
  cashu.c
  lightning.c
  voucher.c
)

target_include_directories(payment PUBLIC ${PROJECT_SOURCE_DIR}/src)
