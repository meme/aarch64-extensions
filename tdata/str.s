/*
 * aarch64-linux-gnu-as -mcpu=all str.s -o str.o
 */

_start:
    /* Store vector registers (stack offset) */
    str     b0, [sp, #0x610]
    str     h0, [sp, #0x610]
    str     s0, [sp, #0x610]
    str     d0, [sp, #0x610]
    str     q0, [sp, #0x610]

    /* Post-index */
    str     b0, [x0], #0xf0
    str     h0, [x0], #0xf0
    str     s0, [x0], #0xf0
    str     d0, [x0], #0xf0
    str     q0, [x0], #0xf0

    /* Pre-index with writeback */
    str     b0, [x0, #0xfc]!
    str     h0, [x0, #0xfc]!
    str     s0, [x0, #0xfc]!
    str     d0, [x0, #0xfc]!
    str     q0, [x0, #0xfc]!

    /* Store vector registers (register, no offset) */
    str     b0, [x0]
    str     h0, [x0]
    str     s0, [x0]
    str     d0, [x0]
    str     q0, [x0]

    /* Store full-width vector registers */
/* The manual says this is possible, but GNU as won't assemble it:
    str     v0, [x0, #0x610]
    str     v0, [x0]
*/

    /* Store zero register */
    str     wzr, [x0]
    str     xzr, [x0]

    /* Store with shifted index register */
    str     x0, [x8, x25, lsl #3]
    str     h0, [x8, x25, lsl #1]

    /* Store with extend? */
    str     x0, [x8, w25, uxtw #3]
