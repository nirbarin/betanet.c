#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include "../../src/net/htx/frame.h"
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

// Local helper to write 24-bit big-endian length
static void write_uint24(uint8_t *buf, uint32_t value) {
  buf[0] = (value >> 16) & 0xFF;
  buf[1] = (value >> 8) & 0xFF;
  buf[2] = value & 0xFF;
}

// Stub crypto context
typedef struct bn_htx_crypto_ctx {
  int dummy;
} bn_htx_crypto_ctx_t;

static bn_htx_crypto_ctx_t stub_crypto = {0};

// Test create_stream
void test_create_stream(void) {
  uint8_t buffer[1024];
  size_t frame_len;
  int res = bn_htx_frame_create_stream(buffer, sizeof(buffer), 1, (uint8_t*)"hello", 5, &frame_len);
  CU_ASSERT_EQUAL(res, BN_HTX_SUCCESS);
  CU_ASSERT_EQUAL(frame_len, 1 + 1 + 5); // type + varint(1=1 byte) + data
  CU_ASSERT_EQUAL(buffer[0], BN_HTX_FRAME_STREAM);
  CU_ASSERT_EQUAL(buffer[1], 1); // stream_id=1
  CU_ASSERT_EQUAL(memcmp(buffer + 2, "hello", 5), 0);
}

// Test create_ping
void test_create_ping(void) {
  uint8_t buffer[1024];
  size_t frame_len;
  int res = bn_htx_frame_create_ping(buffer, sizeof(buffer), &frame_len);
  CU_ASSERT_EQUAL(res, BN_HTX_SUCCESS);
  CU_ASSERT_EQUAL(frame_len, 1);
  CU_ASSERT_EQUAL(buffer[0], BN_HTX_FRAME_PING);
}

// Test create_close
void test_create_close(void) {
  uint8_t buffer[1024];
  size_t frame_len;
  int res = bn_htx_frame_create_close(buffer, sizeof(buffer), 100, "test reason", &frame_len);
  CU_ASSERT_EQUAL(res, BN_HTX_SUCCESS);
  CU_ASSERT_EQUAL(frame_len, 1 + 2 + 2 + 11); // type + ec + rl + reason
  CU_ASSERT_EQUAL(buffer[0], BN_HTX_FRAME_CLOSE);
  uint16_t ec = ntohs(*(uint16_t*)(buffer + 1));
  CU_ASSERT_EQUAL(ec, 100);
  uint16_t rl = ntohs(*(uint16_t*)(buffer + 3));
  CU_ASSERT_EQUAL(rl, 11);
  CU_ASSERT_EQUAL(memcmp(buffer + 5, "test reason", 11), 0);
}

// Test create_key_update
void test_create_key_update(void) {
  uint8_t buffer[1024];
  size_t frame_len;
  int res = bn_htx_frame_create_key_update(buffer, sizeof(buffer), &frame_len);
  CU_ASSERT_EQUAL(res, BN_HTX_SUCCESS);
  CU_ASSERT_EQUAL(frame_len, 1);
  CU_ASSERT_EQUAL(buffer[0], BN_HTX_FRAME_KEY_UPDATE);
}

// Test create_window_update
void test_create_window_update(void) {
  uint8_t buffer[1024];
  size_t frame_len;
  int res = bn_htx_frame_create_window_update(buffer, sizeof(buffer), 1, 1000, &frame_len);
  CU_ASSERT_EQUAL(res, BN_HTX_SUCCESS);
  CU_ASSERT_EQUAL(frame_len, 1 + 1 + 4); // type + varint + inc
  CU_ASSERT_EQUAL(buffer[0], BN_HTX_FRAME_WINDOW_UPDATE);
  uint32_t inc = ntohl(*(uint32_t*)(buffer + 2));
  CU_ASSERT_EQUAL(inc, 1000);
}

// Test parse (stubbed, since no real encrypt/decrypt)
void test_parse(void) {
  // Create a mock wire frame: len24(5) + type(0) + sid(1) + ct(5) + tag(16 zeros)
  uint8_t wire[3 + 1 + 1 + 5 + 16];
  write_uint24(wire, 5);
  wire[3] = BN_HTX_FRAME_STREAM;
  wire[4] = 1; // sid
  memset(wire + 5, 'a', 5); // ct
  memset(wire + 10, 0, 16); // tag
  bn_htx_frame_t frame = {0};
  size_t consumed;
  int res = bn_htx_frame_parse(wire, sizeof(wire), &frame, &consumed);
  CU_ASSERT_EQUAL(res, BN_HTX_SUCCESS);
  CU_ASSERT_EQUAL(frame.length, 5);
  CU_ASSERT_EQUAL(frame.type, BN_HTX_FRAME_STREAM);
  CU_ASSERT_EQUAL(frame.stream_id, 1);
  CU_ASSERT_EQUAL(frame.ciphertext_len, 5);
  CU_ASSERT_EQUAL(consumed, 3 + 1 + 1 + 5 + 16);
  // frame.ciphertext points into 'wire' buffer; do not free it here
}

// Test encrypt stub
void test_encrypt(void) {
  bn_htx_frame_t frame = {0};
  frame.type = BN_HTX_FRAME_STREAM;
  frame.has_stream_id = true;
  frame.stream_id = 1;
  frame.payload = (uint8_t*)"hello";
  frame.payload_len = 5;
  uint8_t output[1024];
  size_t out_len;
  int res = bn_htx_frame_encrypt(&stub_crypto, &frame, output, sizeof(output), &out_len);
  CU_ASSERT_EQUAL(res, BN_HTX_SUCCESS);
  // Check length etc., stubbed so basic
  CU_ASSERT(out_len > 0);
}

// Test decrypt stub
void test_decrypt(void) {
  uint8_t mock_wire[50] = {0}; // similar to parse
  write_uint24(mock_wire, 5);
  mock_wire[3] = BN_HTX_FRAME_STREAM;
  mock_wire[4] = 1;
  memcpy(mock_wire + 5, "hello", 5);
  memset(mock_wire + 10, 0, 16);
  bn_htx_frame_t frame = {0};
  int res = bn_htx_frame_decrypt(&stub_crypto, mock_wire, sizeof(mock_wire), &frame);
  CU_ASSERT_EQUAL(res, BN_HTX_SUCCESS);
  CU_ASSERT_EQUAL(frame.payload_len, 5);
  CU_ASSERT_EQUAL(memcmp(frame.payload, "hello", 5), 0);
  free(frame.payload);
}

int main(void) {
  CU_pSuite pSuite = NULL;
  if (CUnit_initialize_registry() != CUE_SUCCESS) return CU_get_error();
  pSuite = CU_add_suite("HTX Frame Suite", NULL, NULL);
  if (pSuite == NULL) return CU_get_error();
  CU_add_test(pSuite, "create_stream", test_create_stream);
  CU_add_test(pSuite, "create_ping", test_create_ping);
  CU_add_test(pSuite, "create_close", test_create_close);
  CU_add_test(pSuite, "create_key_update", test_create_key_update);
  CU_add_test(pSuite, "create_window_update", test_create_window_update);
  CU_add_test(pSuite, "parse", test_parse);
  CU_add_test(pSuite, "encrypt", test_encrypt);
  CU_add_test(pSuite, "decrypt", test_decrypt);
  CU_basic_set_mode(CU_BRM_VERBOSE);
  CU_basic_run_tests();
  CU_cleanup_registry();
  return CU_get_error();
}
