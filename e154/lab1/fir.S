.global fir

fir: // implement fir(int x[], int c[], int y[], int n, int m)

    // save s0-s3 and s7-s11 on the stack
    addi sp, sp, -80

    sd s0, 0(sp)
    sd s1, 8(sp)
    sd s2, 16(sp)
    sd s3, 24(sp)
    sd s7, 32(sp)
    sd s8, 40(sp)
    sd s9, 48(sp)
    sd s10, 56(sp)
    sd s11, 64(sp)
    sd ra , 72(sp) // save return address

    // save a0-a4, as these aren't guaranteed to be preserved

    mv s11, a4 // s11 = m
    mv s10, a3 // s10 = n
    mv s9, a2 // s9 = y
    mv s8, a1 // s8 = c
    mv s7, a0 // s7 = x

    // calculate num_outputs = n - m + 1
    addi s0, s10, 1     // s0 = n + 1
    sub s0, s0, s11     // s0 = n - m + 1

    li s1, 0           // j = 0
innerLoop:
    bge s1, s0, endInnerLoop   // while (j < num_outputs)

    li s2, 0           // accumulator y[j] = 0
    li s3, 0           // i = 0

innerLoop2:
    bge s3, s11, endInnerLoop2  // while (i < m)

    // calculate x-index: j - i + m - 1
    add t0, s1, s11    // t0 = j + m
    sub t0, t0, s3    // t0 = j + m - i
    addi t0, t0, -1   // t0 = j - i + m - 1
    slli t0, t0, 2    // word offset

    add t0, t0, s7    // address for x[ j-i+m-1 ]
    lw a0, 0(t0)      // load x element into t2

    // calculate address for c[i]
    slli t1, s3, 2    // word offset
    add t1, t1, s8    // address for c[i]
    lw a1, 0(t1)     // load c element into t5

    // call mul_q31 with a0 = x element, a1 = c element
    jal mul_q31     // product in a0

    // add result to y[j] using add_q31
    mv a1, s2      // a1 = current y[j]
    jal add_q31    // result in a0
    mv s2, a0      // update accumulator

    addi s3, s3, 1 // i++
    j innerLoop2

endInnerLoop2:
    // store computed y[j] into y[j]
    slli t0, s1, 2
    add t0, t0, s9
    sw s2, 0(t0)

    addi s1, s1, 1 // j++
    j innerLoop

endInnerLoop:
    // restore s0-s3 and s7-s11 from the stack
    ld s0, 0(sp)
    ld s1, 8(sp)
    ld s2, 16(sp)
    ld s3, 24(sp)
    ld s7, 32(sp)
    ld s8, 40(sp)
    ld s9, 48(sp)
    ld s10, 56(sp)
    ld s11, 64(sp)
    ld ra , 72(sp) // restore return address
    addi sp, sp, 80
    ret