#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>

// One short NDEF Text (UTF-8, language ru) or URI record in a Type 2 TLV.
// Bounded to short records; no dynamic allocation and no tag configuration writes.
inline size_t buildNdef(const uint8_t* text, size_t len, bool uri,
                        uint8_t* out, size_t capacity) {
  const size_t prefix = uri ? 1 : 3;
  if (!text || !out || len == 0 || len > 255 - prefix) return 0;
  const size_t recordLen = 4 + prefix + len;
  const size_t tlvHeader = recordLen < 255 ? 2 : 4;
  const size_t total = tlvHeader + recordLen + 1;
  if (total > capacity) return 0;
  size_t p = 0;
  out[p++] = 0x03;
  if (recordLen < 255) out[p++] = uint8_t(recordLen);
  else { out[p++] = 0xFF; out[p++] = uint8_t(recordLen >> 8); out[p++] = uint8_t(recordLen); }
  out[p++] = 0xD1; out[p++] = 1; out[p++] = uint8_t(prefix + len);
  out[p++] = uri ? 'U' : 'T';
  if (uri) out[p++] = 0; // Complete URI, no prefix compression.
  else { out[p++] = 2; out[p++] = 'r'; out[p++] = 'u'; }
  memcpy(out + p, text, len); p += len;
  out[p++] = 0xFE;
  return p;
}

inline bool isClassicDataBlock(unsigned block, unsigned blockCount) {
  if (block == 0 || block >= blockCount) return false;
  return block < 128 ? block % 4 != 3 : block % 16 != 15;
}

inline int hexDigit(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}
inline bool parseHex(const char* s, uint8_t* dst, size_t count) {
  size_t i = 0; int high = -1;
  for (; *s; ++s) {
    if (*s == ' ' || *s == ':' || *s == '\r' || *s == '\n' || *s == '\t') continue;
    int v = hexDigit(*s);
    if (v < 0) return false;
    if (high < 0) high = v;
    else { if (i == count) return false; dst[i++] = uint8_t((high << 4) | v); high = -1; }
  }
  return high < 0 && i == count;
}
