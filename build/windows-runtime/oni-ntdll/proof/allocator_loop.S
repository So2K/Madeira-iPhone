/* Wine ntdll RtlAllocateHeap canonical bitmap-clear loop.
 * Register-allocation compatibility backport for Madeira's ml1284 alias CAS.
 * Based on the exact original Wine PE supplied with official Madeira c2c1b03a9e36ef986c980b9eae3c14d05a372db1.
 * This assembly modification is LGPL-2.1-or-later; see licenses/LGPL-2.1.txt.
 * This is the complete changed code, not source for rebuilding all of Wine.
 */
.text
.p2align 2
.global original_loop
original_loop:
.Loriginal_retry:
    ldaxr w11, [x8]
    and w11, w11, w10
    stlxr w12, w11, [x8]
    cbnz w12, .Loriginal_retry
.global patched_loop
patched_loop:
.Lpatched_retry:
    ldaxr w12, [x8]
    and w11, w12, w10
    stlxr w12, w11, [x8]
    cbnz w12, .Lpatched_retry
