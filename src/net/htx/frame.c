#include "frame.h"
#include "noise.h"  // For crypto functions, stubbed for now
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>  // For htons, htonl

// Helper functions for serialization

static int write_uint24(uint8_t *buf, uint32_t value) {
  if (value > 0xFFFFFFu) return BN_HTX_INVALID_LENGTH;
  buf[0] = (value >> 16) & 0xFF;
  buf[1] = (value >> 8) & 0xFF;
  buf[2] = value & 0xFF;
  return BN_HTX_SUCCESS;
}

static int read_uint24(const uint8_t *buf, uint32_t *value) {
  *value = ((uint32_t)buf[0] << 16) | (buf[1] << 8) | buf[2];
  return BN_HTX_SUCCESS;
}

static size_t varint_encode(uint64_t value, uint8_t *buf) {
  size_t len = 0;
  do {
    uint8_t byte = value & 0x7F;
    value >>= 7;
    if (value != 0) byte |= 0x80;
    buf[len++] = byte;
  } while (value != 0);
  return len;
}

static int varint_decode(const uint8_t *buf, size_t buf_len, uint64_t *value, size_t *consumed) {
  *value = 0;
  *consumed = 0;
  uint64_t v = 0;
  size_t shift = 0;
  const uint8_t *p = buf;
  while (*consumed < buf_len) {
    uint8_t byte = *p++;
    v |= ((uint64_t)(byte & 0x7F)) << shift;
    shift += 7;
    (*consumed)++;
    if ((byte & 0x80) == 0) {
      *value = v;
      return BN_HTX_SUCCESS;
    }
    if (shift >= 64) return BN_HTX_INVALID_FRAME;
  }
  return BN_HTX_INVALID_FRAME;
}

// bn_htx_frame_create_stream - outputs inner plaintext: type + stream_id varint + data
int bn_htx_frame_create_stream(uint8_t *buffer, size_t buffer_size, 
                               uint64_t stream_id, const uint8_t *data, 
                               size_t data_len, size_t *frame_len) {
  if (buffer_size < 1 + 20 + data_len) return BN_HTX_ERROR; // conservative
  uint8_t *p = buffer;
  *p++ = BN_HTX_FRAME_STREAM;
  size_t var_len = varint_encode(stream_id, p);
  p += var_len;
  if (p + data_len > buffer + buffer_size) return BN_HTX_ERROR;
  if (data_len > 0) memcpy(p, data, data_len);
  *frame_len = (p - buffer) + data_len;
  return BN_HTX_SUCCESS;
}

// bn_htx_frame_create_ping - inner: type
int bn_htx_frame_create_ping(uint8_t *buffer, size_t buffer_size, size_t *frame_len) {
  if (buffer_size < 1) return BN_HTX_ERROR;
  buffer[0] = BN_HTX_FRAME_PING;
  *frame_len = 1;
  return BN_HTX_SUCCESS;
}

// bn_htx_frame_create_close - inner: type + payload (uint16 error + uint16 len + reason)
int bn_htx_frame_create_close(uint8_t *buffer, size_t buffer_size, 
                              uint16_t error_code, const char *reason, 
                              size_t *frame_len) {
  size_t reason_len = strlen(reason);
  if (reason_len > 0xFFFF) return BN_HTX_ERROR;
  size_t payload_len = 4 + reason_len;
  if (buffer_size < 1 + payload_len) return BN_HTX_ERROR;
  uint8_t *p = buffer;
  *p++ = BN_HTX_FRAME_CLOSE;
  uint16_t ec_be = htons(error_code);
  memcpy(p, &ec_be, 2);
  p += 2;
  uint16_t rl_be = htons((uint16_t)reason_len);
  memcpy(p, &rl_be, 2);
  p += 2;
  memcpy(p, reason, reason_len);
  p += reason_len;
  *frame_len = p - buffer;
  return BN_HTX_SUCCESS;
}

// bn_htx_frame_create_key_update - inner: type
int bn_htx_frame_create_key_update(uint8_t *buffer, size_t buffer_size, size_t *frame_len) {
  if (buffer_size < 1) return BN_HTX_ERROR;
  buffer[0] = BN_HTX_FRAME_KEY_UPDATE;
  *frame_len = 1;
  return BN_HTX_SUCCESS;
}

// bn_htx_frame_create_window_update - inner: type + stream_id varint + uint32 increment
int bn_htx_frame_create_window_update(uint8_t *buffer, size_t buffer_size, 
                                      uint64_t stream_id, uint32_t increment, 
                                      size_t *frame_len) {
  if (buffer_size < 1 + 20 + 4) return BN_HTX_ERROR;
  uint8_t *p = buffer;
  *p++ = BN_HTX_FRAME_WINDOW_UPDATE;
  size_t var_len = varint_encode(stream_id, p);
  p += var_len;
  uint32_t inc_be = htonl(increment);
  memcpy(p, &inc_be, 4);
  *frame_len = (p - buffer) + 4;
  return BN_HTX_SUCCESS;
}

// bn_htx_frame_parse - parses wire: length(3) + inner (type + ... + ciphertext(len)) + tag(16)
int bn_htx_frame_parse(const uint8_t *buffer, size_t buffer_size, 
                       bn_htx_frame_t *frame, size_t *consumed) {
  if (buffer_size < 4) return BN_HTX_INVALID_FRAME;
  uint32_t len;
  int res = read_uint24(buffer, &len);
  if (res < 0) return res;
  frame->length = len;
  const uint8_t *p = buffer + 3;
  if (p + 1 > buffer + buffer_size) return BN_HTX_INVALID_FRAME;
  frame->type = (enum bn_htx_frame_type)*p++;
  frame->has_stream_id = (frame->type == BN_HTX_FRAME_STREAM || frame->type == BN_HTX_FRAME_WINDOW_UPDATE);
  size_t var_cons = 0;
  if (frame->has_stream_id) {
    res = varint_decode(p, buffer_size - (p - buffer), &frame->stream_id, &var_cons);
    if (res < 0) return res;
    p += var_cons;
  } else {
    frame->stream_id = 0;
    var_cons = 0;
  }
  size_t header_len = (p - buffer); // 3 + type + var
  size_t ct_start = header_len;
  size_t remaining = buffer_size - header_len;
  if (remaining < len + 16) return BN_HTX_INVALID_LENGTH;
  frame->ciphertext = (uint8_t *)p;
  frame->ciphertext_len = len;
  frame->payload = NULL;
  frame->payload_len = 0;
  *consumed = header_len + len + 16;
  return BN_HTX_SUCCESS;
}

// bn_htx_frame_encrypt - serializes inner from frame.payload, encrypts with aad = type + stream_id, outputs wire
int bn_htx_frame_encrypt(const bn_htx_crypto_ctx_t *crypto_ctx, 
                         bn_htx_frame_t *frame, 
                         uint8_t *output, size_t output_size, 
                         size_t *output_len) {
  // Serialize aad = type + stream_id if has
  uint8_t aad[32];
  uint8_t *a = aad;
  *a++ = frame->type;
  size_t aad_len = 1;
  if (frame->has_stream_id) {
    size_t var_len = varint_encode(frame->stream_id, a);
    a += var_len;
    aad_len += var_len;
  }
  // Plaintext = frame->payload
  const uint8_t *plaintext = frame->payload;
  size_t pt_len = frame->payload_len;
  // Encrypt: assume bn_noise_encrypt_aad(crypto_ctx, counter, aad, aad_len, plaintext, pt_len, ciphertext, tag)
  // Stub: ciphertext = plaintext, tag = 0
  uint8_t ciphertext[1024]; // assume
  uint8_t tag[16];
  memcpy(ciphertext, plaintext, pt_len);
  memset(tag, 0, 16);
  size_t ct_len = pt_len;
  uint32_t len_excl = (uint32_t)ct_len;
  if (len_excl > 0xFFFFFFu) return BN_HTX_INVALID_LENGTH;
  size_t total = 3 + aad_len + ct_len + 16;
  if (output_size < total) return BN_HTX_ERROR;
  uint8_t *out = output;
  int res = write_uint24(out, len_excl);
  if (res < 0) return res;
  out += 3;
  memcpy(out, aad, aad_len);
  out += aad_len;
  memcpy(out, ciphertext, ct_len);
  out += ct_len;
  memcpy(out, tag, 16);
  *output_len = total;
  return BN_HTX_SUCCESS;
}

// bn_htx_frame_decrypt
int bn_htx_frame_decrypt(const bn_htx_crypto_ctx_t *crypto_ctx, 
                         const uint8_t *buffer, size_t buffer_size, 
                         bn_htx_frame_t *frame) {
  size_t consumed;
  int res = bn_htx_frame_parse(buffer, buffer_size, frame, &consumed);
  if (res < 0) return res;
  // Extract aad = buffer +3 to before ciphertext
  size_t aad_start = 3;
  size_t aad_len = (frame->ciphertext - buffer) - 3;
  const uint8_t *ct = frame->ciphertext;
  size_t ct_len = frame->ciphertext_len;
  const uint8_t *tag = ct + ct_len;
  // Decrypt
  uint8_t *plaintext = malloc(ct_len);
  if (!plaintext) return BN_HTX_ERROR;
  // Stub bn_noise_decrypt_aad(crypto_ctx, counter, aad, aad_len, ct, ct_len, tag, plaintext, &pt_len)
  // Stub
  memcpy(plaintext, ct, ct_len);
  size_t pt_len = ct_len;
  frame->payload = plaintext;
  frame->payload_len = pt_len;
  return BN_HTX_SUCCESS;
}
