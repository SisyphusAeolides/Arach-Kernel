.section .text,"ax"
.code64

.equ USER_DATA_SELECTOR, 0x1b
.equ USER_CODE_SELECTOR, 0x23
.equ CR4_OSFXSR, (1 << 9)
.equ CR4_OSXMMEXCPT, (1 << 10)
.equ CR4_OSXSAVE, (1 << 18)
.equ CPUID_XSAVE, (1 << 26)
.equ CPUID_OSXSAVE, (1 << 27)
.equ CPUID_AVX, (1 << 28)

.global arach_enter_ring3_probe
.type arach_enter_ring3_probe, @function
arach_enter_ring3_probe:
    pushq %rbp
    pushq %rbx
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    movq %rsp, ring3_saved_rsp(%rip)
    movq %cr3, %rax
    movq %rax, ring3_saved_cr3(%rip)
    movq %rdx, %cr3

    pushq $USER_DATA_SELECTOR
    pushq %rsi
    pushfq
    popq %rax
    andq $-13057, %rax
    pushq %rax
    pushq $USER_CODE_SELECTOR
    pushq %rdi
    iretq
.size arach_enter_ring3_probe, . - arach_enter_ring3_probe

.global arach_ring3_probe_return
.type arach_ring3_probe_return, @function
arach_ring3_probe_return:
    cli
    movq ring3_saved_cr3(%rip), %rax
    movq %rax, %cr3
    movq ring3_saved_rsp(%rip), %rsp
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbx
    popq %rbp
    retq
.size arach_ring3_probe_return, . - arach_ring3_probe_return

.global arach_enter_user_process
.type arach_enter_user_process, @function
arach_enter_user_process:
    cli
    movq %rdx, %cr3
    # x86-64 user code may use the mandatory SSE2 baseline. Advertise the
    # architectural XMM state before iret, and expose AVX only when the
    # processor reports XSAVE, OSXSAVE, and AVX together. Without this, a
    # normal optimized libc startup can receive #UD even though the ISA is
    # present in CPUID because CR4.OSXSAVE/XCR0 were never published.
    movl $1, %eax
    xorl %ecx, %ecx
    cpuid
    movq %cr4, %rax
    orq $(CR4_OSFXSR | CR4_OSXMMEXCPT), %rax
    testl $(CPUID_XSAVE | CPUID_OSXSAVE | CPUID_AVX), %ecx
    jz 1f
    orq $CR4_OSXSAVE, %rax
    movq %rax, %cr4
    xorl %ecx, %ecx
    xgetbv
    orl $0x7, %eax
    xorl %edx, %edx
    xsetbv
    jmp 2f
1:
    movq %rax, %cr4
2:
    fninit
    # A statically linked Linux image has no dynamic-linker finalizer. The
    # SysV entry contract leaves the runtime-linker hook in RDX, so publish a
    # null hook after the page-table root has been consumed instead of
    # leaking the kernel's setup value into Ring 3.
    xorq %rdx, %rdx
    pushq $USER_DATA_SELECTOR
    pushq %rsi
    pushq $0x202
    pushq $USER_CODE_SELECTOR
    pushq %rdi
    iretq
    ud2
.size arach_enter_user_process, . - arach_enter_user_process

.section .bss,"aw",@nobits
.balign 8
ring3_saved_rsp:
    .quad 0
ring3_saved_cr3:
    .quad 0
