/* SPDX-License-Identifier: MIT
 * Packed D3D12 ExecuteIndirect layouts used by the default-off reference path.
 * No Windows/Metal types: the identical decoder is exercised by host tests. */
#ifndef MADEIRA_INDIRECT_REFERENCE_DECODE_H
#define MADEIRA_INDIRECT_REFERENCE_DECODE_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>

struct mad_ir_layout {
    uint32_t stride, payload, root_index, vb_slot;
    uint8_t valid, indexed, views;
};
struct mad_ir_record {
    uint64_t cbv, vb_address, ib_address;
    uint32_t vb_size, vb_stride, ib_size, ib_format;
    uint32_t count, instances, start, first_instance;
    int32_t base_vertex;
};
static int mad_ir_layout_init(struct mad_ir_layout *l, const uint32_t *types,
                              uint32_t n, uint32_t stride, uint32_t root,
                              uint32_t vb_slot) {
    memset(l, 0, sizeof *l);
    if (!types || root >= 32 || !stride || (stride & 3)) return 0;
    if (n == 2 && types[0] == 6 && (types[1] == 0 || types[1] == 1)) {
        l->indexed = types[1] == 1; l->payload = l->indexed ? 28 : 24;
    } else if (n == 4 && types[0] == 6 && types[1] == 3 &&
               types[2] == 4 && types[3] == 1 && vb_slot < 16) {
        l->indexed = l->views = 1; l->payload = 60;
    } else return 0;
    if (stride < l->payload) { memset(l, 0, sizeof *l); return 0; }
    l->stride = stride; l->root_index = root; l->vb_slot = vb_slot;
    return l->valid = 1;
}
/* Validate the whole declared stride extent; copy only bytes actually read.
 * No addition/multiply occurs before subtraction/division proves it fits. */
static int mad_ir_span(uint64_t size, uint64_t off, uint32_t count,
                       const struct mad_ir_layout *l, uint64_t *span) {
    *span = 0;
    if (!l->valid || (off & 3) || off > size) return 0;
    if (!count) return 1;
    if (!l->stride || l->stride < l->payload ||
        (uint64_t)count > (size - off) / l->stride) return 0;
    *span = (uint64_t)(count - 1) * l->stride + l->payload;
    return 1;
}
static uint32_t mad_ir_u32(const void *p) { uint32_t v; memcpy(&v, p, 4); return v; }
static uint64_t mad_ir_u64(const void *p) { uint64_t v; memcpy(&v, p, 8); return v; }
static uint32_t mad_ir_count(uint32_t maximum, const void *count) {
    uint32_t n = count ? mad_ir_u32(count) : maximum;
    return n < maximum ? n : maximum;
}
static int mad_ir_decode(const struct mad_ir_layout *l, const void *bytes,
                         size_t available, struct mad_ir_record *r) {
    const unsigned char *p = bytes;
    memset(r, 0, sizeof *r);
    if (!l->valid || !bytes || available < l->payload) return 0;
    r->cbv = mad_ir_u64(p); p += 8;
    if (l->views) {
        r->vb_address = mad_ir_u64(p); r->vb_size = mad_ir_u32(p + 8);
        r->vb_stride = mad_ir_u32(p + 12); p += 16;
        r->ib_address = mad_ir_u64(p); r->ib_size = mad_ir_u32(p + 8);
        r->ib_format = mad_ir_u32(p + 12); p += 16;
    }
    r->count = mad_ir_u32(p); r->instances = mad_ir_u32(p + 4);
    r->start = mad_ir_u32(p + 8);
    if (l->indexed) {
        memcpy(&r->base_vertex, p + 12, 4); r->first_instance = mad_ir_u32(p + 16);
    } else r->first_instance = mad_ir_u32(p + 12);
    return 1;
}
#endif
