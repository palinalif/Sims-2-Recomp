/* Android/Bionic AArch64 static executables require PT_TLS alignment >= 64.
 * Reserve ABI padding only: no guest state or replacement game behavior.
 * This is assembly because API26 clang uses emulated TLS for C/C++ variables.
 * Keep this input out of the Android shared-library/app build.
 */
.section .tbss.ts2_static_tls_alignment,"awT",@nobits
.p2align 6
.byte 0
.section .note.GNU-stack,"",@progbits
