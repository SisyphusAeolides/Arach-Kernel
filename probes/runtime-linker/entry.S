.section .text.entry,"ax",@progbits
.global _start
.type _start,@function
_start:
    mov %rsp, %rdi
    call arach_runtime_linker_start
    test %rax, %rax
    jz .Linvalid_entry
    jmp *%rax
.Linvalid_entry:
    ud2
.size _start, .-_start

.section .note.GNU-stack,"",@progbits
