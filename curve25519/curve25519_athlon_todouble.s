.text
.p2align 5
.globl _curve25519_athlon_todouble
.globl curve25519_athlon_todouble
_curve25519_athlon_todouble:
curve25519_athlon_todouble:
mov %esp,%eax
and $31,%eax
add $96,%eax
sub %eax,%esp
movl 8(%esp,%eax),%ecx
movl 0(%ecx),%edx
movl  $0x43300000,4(%esp)
movl %edx,0(%esp)
movl 4(%ecx),%edx
and  $0xffffff,%edx
movl  $0x45300000,12(%esp)
movl %edx,8(%esp)
movl 7(%ecx),%edx
and  $0xffffff,%edx
movl  $0x46b00000,20(%esp)
movl %edx,16(%esp)
movl 10(%ecx),%edx
and  $0xffffff,%edx
movl  $0x48300000,28(%esp)
movl %edx,24(%esp)
movl 13(%ecx),%edx
and  $0xffffff,%edx
movl  $0x49b00000,36(%esp)
movl %edx,32(%esp)
movl 16(%ecx),%edx
movl  $0x4b300000,44(%esp)
movl %edx,40(%esp)
movl 20(%ecx),%edx
and  $0xffffff,%edx
movl  $0x4d300000,52(%esp)
movl %edx,48(%esp)
movl 23(%ecx),%edx
and  $0xffffff,%edx
movl  $0x4eb00000,60(%esp)
movl %edx,56(%esp)
movl 26(%ecx),%edx
and  $0xffffff,%edx
movl  $0x50300000,68(%esp)
movl %edx,64(%esp)
movl 28(%ecx),%ecx
shr  $8,%ecx
and  $0x7fffff,%ecx
movl  $0x51b00000,76(%esp)
movl %ecx,72(%esp)
movl 4(%esp,%eax),%ecx
fldl 72(%esp)
fsubl curve25519_athlon_in9offset
fldl curve25519_athlon_alpha255
fadd %st(1),%st(0)
fsubl curve25519_athlon_alpha255
fsubr %st(0),%st(1)
fldl 0(%esp)
fsubl curve25519_athlon_in0offset
fxch %st(1)
fmull curve25519_athlon_scale
faddp %st(0),%st(1)
fldl curve25519_athlon_alpha26
fadd %st(1),%st(0)
fsubl curve25519_athlon_alpha26
fsubr %st(0),%st(1)
fxch %st(1)
fstpl 0(%ecx)
fldl 8(%esp)
fsubl curve25519_athlon_in1offset
faddp %st(0),%st(1)
fldl curve25519_athlon_alpha51
fadd %st(1),%st(0)
fsubl curve25519_athlon_alpha51
fsubr %st(0),%st(1)
fxch %st(1)
fstpl 8(%ecx)
fldl 16(%esp)
fsubl curve25519_athlon_in2offset
faddp %st(0),%st(1)
fldl curve25519_athlon_alpha77
fadd %st(1),%st(0)
fsubl curve25519_athlon_alpha77
fsubr %st(0),%st(1)
fxch %st(1)
fstpl 16(%ecx)
fldl 24(%esp)
fsubl curve25519_athlon_in3offset
faddp %st(0),%st(1)
fldl curve25519_athlon_alpha102
fadd %st(1),%st(0)
fsubl curve25519_athlon_alpha102
fsubr %st(0),%st(1)
fxch %st(1)
fstpl 24(%ecx)
fldl 32(%esp)
fsubl curve25519_athlon_in4offset
faddp %st(0),%st(1)
fldl curve25519_athlon_alpha128
fadd %st(1),%st(0)
fsubl curve25519_athlon_alpha128
fsubr %st(0),%st(1)
fxch %st(1)
fstpl 32(%ecx)
fldl 40(%esp)
fsubl curve25519_athlon_in5offset
faddp %st(0),%st(1)
fldl curve25519_athlon_alpha153
fadd %st(1),%st(0)
fsubl curve25519_athlon_alpha153
fsubr %st(0),%st(1)
fxch %st(1)
fstpl 40(%ecx)
fldl 48(%esp)
fsubl curve25519_athlon_in6offset
faddp %st(0),%st(1)
fldl curve25519_athlon_alpha179
fadd %st(1),%st(0)
fsubl curve25519_athlon_alpha179
fsubr %st(0),%st(1)
fxch %st(1)
fstpl 48(%ecx)
fldl 56(%esp)
fsubl curve25519_athlon_in7offset
faddp %st(0),%st(1)
fldl curve25519_athlon_alpha204
fadd %st(1),%st(0)
fsubl curve25519_athlon_alpha204
fsubr %st(0),%st(1)
fxch %st(1)
fstpl 56(%ecx)
fldl 64(%esp)
fsubl curve25519_athlon_in8offset
faddp %st(0),%st(1)
fldl curve25519_athlon_alpha230
fadd %st(1),%st(0)
fsubl curve25519_athlon_alpha230
fsubr %st(0),%st(1)
fxch %st(1)
fstpl 64(%ecx)
faddp %st(0),%st(1)
fstpl 72(%ecx)
add %eax,%esp
ret
#if defined(__linux__) && defined(__ELF__)
.section .note.GNU-stack,"",%progbits
#endif
