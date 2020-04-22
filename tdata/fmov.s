/*
 * aarch64-linux-gnu-as -mcpu=cortex-a77 fmov.s -o fmov.o
 */

_start:
    /* FMOV (vector, immediate) */
    fmov    v0.2d, #1.5e+00
    fmov    v0.2s, #1.5e+00
    fmov    v0.4s, #1.5e+00
    fmov    v0.4h, #1.5e+00
    fmov    v0.8h, #1.5e+00

    /* FMOV (register) */
    fmov    d1, d0
    fmov    s1, s0
    fmov    h1, h0

    /* FMOV (general) */
    fmov    w0, h1      /* Half-precision to 32-bit */
    fmov    x0, h1      /* Half-precision to 64-bit */
    fmov    h0, w1      /* 32-bit to half-precision */
    fmov    s0, w1      /* 32-bit to single-precision */
    fmov    w0, s1      /* Single-precision to 32-bit */
    fmov    h0, x1      /* 64-bit to half-precision */
    fmov    d0, x1      /* 64-bit to double-precision */
    fmov    v0.d[1], x1 /* 64-bit to top half of 128-bit */
    fmov    x0, d1      /* Double-precision to 64-bit */
    fmov    x0, v0.d[1] /* Top half of 128-bit to 64-bit  */

    /* FMOV (scalar, immediate) */
    fmov    d0, #1.5e+00
    fmov    s0, #1.5e+00
    fmov    h0, #1.5e+00
