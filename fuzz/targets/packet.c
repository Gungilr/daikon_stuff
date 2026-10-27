/*
 * packet.c - a tiny packet parser. Header: u16 magic, u8 type, u8 len, then
 * the payload.
 *
 * Planted bugs:
 *   packet_copy_overflow  (memory) type 3 copies `len` payload bytes into a
 *                         16-byte stack buffer without checking len. Needs the
 *                         magic 0xBEEF, type 3 AND len > 16 together.
 *   checksum_negative     (logic)  checksum() sums payload bytes as SIGNED
 *                         char, so a byte >= 0x80 makes the documented 0..255
 *                         checksum negative.
 */
#include "../runtime/fuzz.h"

int checksum(const unsigned char *p, int n) {
    int s = 0;
    for (int i = 0; i < n; i++)
        s = (s + (signed char)p[i]) % 256;     /* bug: should be unsigned */
    FUZZ_BUG("checksum_negative", s < 0);
    return s;
}

int copy_record(const unsigned char *payload, int len) {
    unsigned char out[16];
    FUZZ_BUG_FATAL("packet_copy_overflow", len > 16);
    for (int i = 0; i < len; i++)              /* bug: no bound on len */
        out[i] = payload[i];
    return out[0];
}

int parse(int magic, int type, int len, const unsigned char *payload, int avail) {
    if (magic != 0xBEEF)
        return -1;
    if (type == 3)
        return copy_record(payload, len);
    if (type == 1)
        return checksum(payload, avail < len ? avail : len);
    return 0;
}

void fuzz_target(const uint8_t *data, size_t size) {
    unsigned char payload[64];
    for (int i = 0; i < 64; i++)
        payload[i] = 0;
    fuzz_cursor c = fuzz_cursor_make(data, size);
    int magic = fuzz_take_u8(&c) | (fuzz_take_u8(&c) << 8);
    int type = fuzz_take_u8(&c);
    int len = fuzz_take_u8(&c);
    int avail = (int)fuzz_take_bytes(&c, payload, 64);
    parse(magic, type, len, payload, avail);
}
