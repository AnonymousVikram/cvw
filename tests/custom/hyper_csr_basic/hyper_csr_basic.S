.option norvc
.section .text.start
.globl _start

_start:
  # HSTATUS: VTSR (22) and VTVM (20)
  li t0, 0x00500000
  csrw 0x600, t0
  csrr t1, 0x600
  li t2, 0x00500000
  and t1, t1, t2
  bne t1, t0, fail

  # HEDELEG: low 16 bits
  li t0, 0xA5A5
  csrw 0x602, t0
  csrr t1, 0x602
  li t2, 0xFFFF
  and t1, t1, t2
  bne t1, t0, fail

  # HIDELEG: low 12 bits
  li t0, 0x5A5
  csrw 0x603, t0
  csrr t1, 0x603
  li t2, 0x0FFF
  and t1, t1, t2
  bne t1, t0, fail

  # HCOUNTEREN
  li t0, 0x5
  csrw 0x606, t0
  csrr t1, 0x606
  bne t1, t0, fail

success:
  # Emit jal x0, 0 to signal testbench completion.
  .word 0x0000006f

fail:
  beq x0, x0, fail
