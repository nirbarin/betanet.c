#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include "net/htx/htx.h"
#include "net/htx/frame.h"

#define TEST_ASSERT(condition, message) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "FAIL: %s (Line %d)\n", message, __LINE__); \
            return false; \
        } \
    } while (0)

/**
 * Test HTX configuration initialization
 */
static bool test_htx_config_init() {
    printf("Testing HTX configuration initialization...\n");
    
    HTXConfig config;
    int result = htx_config_init(&config);
    TEST_ASSERT(result == 0, "htx_config_init should succeed");
    
    TEST_ASSERT(config.transport_type == HTX_TRANSPORT_TCP, "Default transport should be TCP");
    TEST_ASSERT(config.initial_window_size > 0, "Initial window size should be positive");
    TEST_ASSERT(config.max_streams > 0, "Max streams should be positive");
    TEST_ASSERT(config.ping_interval_ms > 0, "Ping interval should be positive");
    TEST_ASSERT(config.idle_timeout_ms > 0, "Idle timeout should be positive");
    
    /* Test null parameter */
    result = htx_config_init(NULL);
    TEST_ASSERT(result == HTX_ERROR_INVALID_PARAM, "htx_config_init should fail with NULL");
    
    printf("✓ HTX configuration initialization tests passed\n");
    return true;
}

/**
 * Test HTX connection creation and destruction
 */
static bool test_htx_connection_lifecycle() {
    printf("Testing HTX connection lifecycle...\n");
    
    HTXConfig config;
    HTXConnection *conn = NULL;
    
    /* Initialize configuration */
    int result = htx_config_init(&config);
    TEST_ASSERT(result == 0, "Config initialization should succeed");
    
    config.origin_domain = "example.com";
    
    /* Create connection */
    result = htx_connection_create(&config, &conn);
    TEST_ASSERT(result == 0, "Connection creation should succeed");
    TEST_ASSERT(conn != NULL, "Connection pointer should not be NULL");
    
    /* Check initial state */
    HTXConnectionState state;
    result = htx_connection_get_state(conn, &state);
    TEST_ASSERT(result == 0, "Getting connection state should succeed");
    TEST_ASSERT(state == HTX_CONN_STATE_INIT, "Initial state should be INIT");
    
    /* Destroy connection */
    result = htx_connection_destroy(conn);
    TEST_ASSERT(result == 0, "Connection destruction should succeed");
    
    /* Test error cases */
    result = htx_connection_create(NULL, &conn);
    TEST_ASSERT(result == HTX_ERROR_INVALID_PARAM, "Should fail with NULL config");
    
    result = htx_connection_create(&config, NULL);
    TEST_ASSERT(result == HTX_ERROR_INVALID_PARAM, "Should fail with NULL output pointer");
    
    config.origin_domain = NULL;
    result = htx_connection_create(&config, &conn);
    TEST_ASSERT(result == HTX_ERROR_INVALID_STATE, "Should fail with NULL origin domain");
    
    printf("✓ HTX connection lifecycle tests passed\n");
    return true;
}

/**
 * Test HTX frame operations
 */
static bool test_htx_frame_operations() {
    printf("Testing HTX frame operations...\n");
    
    HTXFrame frame;
    
    /* Test frame initialization */
    int result = htx_frame_init(&frame, HTX_FRAME_TYPE_STREAM, HTX_FRAME_FLAG_NONE, 1, 100);
    TEST_ASSERT(result == 0, "Frame initialization should succeed");
    TEST_ASSERT(frame.type == HTX_FRAME_TYPE_STREAM, "Frame type should be set correctly");
    TEST_ASSERT(frame.stream_id == 1, "Stream ID should be set correctly");
    TEST_ASSERT(frame.length == 100, "Frame length should be set correctly");
    
    /* Test setting payload */
    const char *test_data = "Hello, HTX!";
    result = htx_frame_set_payload(&frame, (const uint8_t*)test_data, strlen(test_data));
    TEST_ASSERT(result == 0, "Setting payload should succeed");
    TEST_ASSERT(frame.length == strlen(test_data), "Frame length should match payload");
    
    /* Test getting payload */
    const uint8_t *payload_data;
    size_t payload_size;
    result = htx_frame_get_payload(&frame, &payload_data, &payload_size);
    TEST_ASSERT(result == 0, "Getting payload should succeed");
    TEST_ASSERT(payload_size == strlen(test_data), "Payload size should match");
    TEST_ASSERT(memcmp(payload_data, test_data, payload_size) == 0, "Payload data should match");
    
    /* Test frame serialization */
    uint8_t buffer[1024];
    size_t written;
    result = htx_frame_serialize(&frame, buffer, sizeof(buffer), &written);
    TEST_ASSERT(result == 0, "Frame serialization should succeed");
    TEST_ASSERT(written == HTX_FRAME_HEADER_SIZE + payload_size, "Written size should be correct");
    
    /* Test frame parsing */
    HTXFrame parsed_frame;
    size_t consumed;
    result = htx_frame_parse(buffer, written, &parsed_frame, &consumed);
    TEST_ASSERT(result == 0, "Frame parsing should succeed");
    TEST_ASSERT(consumed == written, "Should consume all bytes");
    TEST_ASSERT(parsed_frame.type == frame.type, "Parsed type should match");
    TEST_ASSERT(parsed_frame.stream_id == frame.stream_id, "Parsed stream ID should match");
    TEST_ASSERT(parsed_frame.length == frame.length, "Parsed length should match");
    
    /* Test frame validation */
    result = htx_frame_validate(&frame);
    TEST_ASSERT(result == 0, "Valid frame should pass validation");
    
    /* Clean up */
    htx_frame_cleanup(&frame);
    htx_frame_cleanup(&parsed_frame);
    
    printf("✓ HTX frame operations tests passed\n");
    return true;
}

/**
 * Test HTX frame helper functions
 */
static bool test_htx_frame_helpers() {
    printf("Testing HTX frame helper functions...\n");
    
    HTXFrame frame;
    int result;
    
    /* Test STREAM frame creation */
    const char *data = "Test stream data";
    result = htx_frame_create_stream(1, (const uint8_t*)data, strlen(data), false, &frame);
    TEST_ASSERT(result == 0, "STREAM frame creation should succeed");
    TEST_ASSERT(frame.type == HTX_FRAME_TYPE_STREAM, "Should be STREAM frame");
    TEST_ASSERT(frame.stream_id == 1, "Stream ID should be 1");
    TEST_ASSERT((frame.flags & HTX_FRAME_FLAG_END_STREAM) == 0, "Should not have END_STREAM flag");
    htx_frame_cleanup(&frame);
    
    /* Test PING frame creation */
    uint8_t ping_data[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    result = htx_frame_create_ping(false, ping_data, &frame);
    TEST_ASSERT(result == 0, "PING frame creation should succeed");
    TEST_ASSERT(frame.type == HTX_FRAME_TYPE_PING, "Should be PING frame");
    TEST_ASSERT(frame.stream_id == 0, "PING frame should have stream ID 0");
    TEST_ASSERT(frame.length == 8, "PING frame should have 8-byte payload");
    htx_frame_cleanup(&frame);
    
    /* Test CLOSE frame creation */
    result = htx_frame_create_close(1, &frame);
    TEST_ASSERT(result == 0, "CLOSE frame creation should succeed");
    TEST_ASSERT(frame.type == HTX_FRAME_TYPE_CLOSE, "Should be CLOSE frame");
    TEST_ASSERT(frame.stream_id == 1, "Stream ID should be 1");
    TEST_ASSERT(frame.length == 0, "CLOSE frame should have no payload");
    htx_frame_cleanup(&frame);
    
    /* Test WINDOW_UPDATE frame creation */
    result = htx_frame_create_window_update(1, 1024, &frame);
    TEST_ASSERT(result == 0, "WINDOW_UPDATE frame creation should succeed");
    TEST_ASSERT(frame.type == HTX_FRAME_TYPE_WINDOW_UPDATE, "Should be WINDOW_UPDATE frame");
    TEST_ASSERT(frame.stream_id == 1, "Stream ID should be 1");
    TEST_ASSERT(frame.length == 4, "WINDOW_UPDATE frame should have 4-byte payload");
    htx_frame_cleanup(&frame);
    
    printf("✓ HTX frame helper tests passed\n");
    return true;
}

/**
 * Test HTX stream operations
 */
static bool test_htx_stream_operations() {
    printf("Testing HTX stream operations...\n");
    
    HTXConfig config;
    HTXConnection *conn;
    HTXStream *stream;
    
    /* Initialize and create connection */
    int result = htx_config_init(&config);
    TEST_ASSERT(result == 0, "Config initialization should succeed");
    
    config.origin_domain = "example.com";
    
    result = htx_connection_create(&config, &conn);
    TEST_ASSERT(result == 0, "Connection creation should succeed");
    
    /* Simulate ready state for stream creation */
    /* In a real implementation, this would be set after handshake completion */
    
    /* Test stream creation when not ready */
    result = htx_stream_create(conn, &stream);
    TEST_ASSERT(result == HTX_ERROR_INVALID_STATE, "Should fail when connection not ready");
    
    /* Test stream operations after cleanup */
    htx_connection_destroy(conn);
    
    printf("✓ HTX stream operations tests passed\n");
    return true;
}

/**
 * Test HTX error conditions
 */
static bool test_htx_error_conditions() {
    printf("Testing HTX error conditions...\n");
    
    /* Test frame operations with invalid parameters */
    HTXFrame frame;
    int result = htx_frame_init(NULL, HTX_FRAME_TYPE_STREAM, 0, 1, 0);
    TEST_ASSERT(result == HTX_ERROR_INVALID_PARAM, "Should fail with NULL frame");
    
    result = htx_frame_init(&frame, HTX_FRAME_TYPE_STREAM, 0, 1, HTX_FRAME_MAX_PAYLOAD_SIZE + 1);
    TEST_ASSERT(result == HTX_ERROR_FRAME_TOO_LARGE, "Should fail with oversized payload");
    
    /* Test frame validation with invalid frames */
    result = htx_frame_init(&frame, HTX_FRAME_TYPE_STREAM, 0, 0, 0);  /* Stream ID 0 invalid for STREAM */
    TEST_ASSERT(result == 0, "Frame init should succeed");
    result = htx_frame_validate(&frame);
    TEST_ASSERT(result == HTX_ERROR_PROTOCOL_VIOLATION, "Should fail validation with stream ID 0");
    htx_frame_cleanup(&frame);
    
    /* Test buffer too small conditions */
    result = htx_frame_init(&frame, HTX_FRAME_TYPE_PING, 0, 0, 0);
    TEST_ASSERT(result == 0, "PING frame init should succeed");
    
    uint8_t small_buffer[4];
    size_t written;
    result = htx_frame_serialize(&frame, small_buffer, sizeof(small_buffer), &written);
    TEST_ASSERT(result == HTX_ERROR_BUFFER_TOO_SMALL, "Should fail with small buffer");
    
    htx_frame_cleanup(&frame);
    
    printf("✓ HTX error condition tests passed\n");
    return true;
}

/**
 * Test data callback mechanism
 */
static bool test_data_callback = false;
static void test_data_callback_func(HTXStream *stream, const uint8_t *data, size_t len, void *user_data) {
    test_data_callback = true;
    printf("Data callback received %zu bytes\n", len);
}

static bool test_htx_data_processing() {
    printf("Testing HTX data processing...\n");
    
    HTXConfig config;
    HTXConnection *conn;
    
    /* Initialize configuration with callback */
    int result = htx_config_init(&config);
    TEST_ASSERT(result == 0, "Config initialization should succeed");
    
    config.origin_domain = "example.com";
    config.data_callback = test_data_callback_func;
    
    result = htx_connection_create(&config, &conn);
    TEST_ASSERT(result == 0, "Connection creation should succeed");
    
    /* Test input processing with no data */
    size_t processed;
    result = htx_connection_process_input(conn, NULL, 0, &processed);
    TEST_ASSERT(result == HTX_ERROR_INVALID_PARAM, "Should fail with NULL data");
    
    /* Test output generation */
    uint8_t output_buffer[1024];
    size_t written;
    result = htx_connection_generate_output(conn, output_buffer, sizeof(output_buffer), &written);
    TEST_ASSERT(result == 0, "Output generation should succeed");
    
    htx_connection_destroy(conn);
    
    printf("✓ HTX data processing tests passed\n");
    return true;
}

/**
 * Main test runner
 */
int main(void) {
    printf("Running HTX Module Tests\n");
    printf("========================\n\n");
    
    bool all_tests_passed = true;
    
    all_tests_passed &= test_htx_config_init();
    all_tests_passed &= test_htx_connection_lifecycle();
    all_tests_passed &= test_htx_frame_operations();
    all_tests_passed &= test_htx_frame_helpers();
    all_tests_passed &= test_htx_stream_operations();
    all_tests_passed &= test_htx_error_conditions();
    all_tests_passed &= test_htx_data_processing();
    
    printf("\n========================\n");
    if (all_tests_passed) {
        printf("✓ All HTX tests PASSED\n");
        return 0;
    } else {
        printf("✗ Some HTX tests FAILED\n");
        return 1;
    }
}