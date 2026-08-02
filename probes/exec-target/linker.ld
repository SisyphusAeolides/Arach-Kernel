ENTRY(_start)

PHDRS
{
    headers PT_PHDR PHDRS FLAGS(4);
    interpreter PT_INTERP FLAGS(4);
    text PT_LOAD FILEHDR PHDRS FLAGS(5);
    rodata PT_LOAD FLAGS(4);
    data PT_LOAD FLAGS(6);
    dynamic PT_DYNAMIC FLAGS(4);
}

SECTIONS
{
    . = SIZEOF_HEADERS;
    .interp :
    {
        BYTE(0x2f) BYTE(0x61) BYTE(0x72) BYTE(0x61) BYTE(0x63) BYTE(0x68)
        BYTE(0x2d) BYTE(0x6c) BYTE(0x64) BYTE(0x2e) BYTE(0x73) BYTE(0x6f)
        BYTE(0x00)
    } :text :interpreter

    .text ALIGN(4K) : { *(.text .text.*) } :text
    .rodata ALIGN(4K) : { *(.rodata .rodata.*) } :rodata
    .hash ALIGN(8) : { *(.hash) } :rodata
    .dynsym : { *(.dynsym) } :rodata
    .dynstr : { *(.dynstr) } :rodata
    .gnu.version : { *(.gnu.version) } :rodata
    .gnu.version_r : { *(.gnu.version_r) } :rodata
    .rela.dyn : { *(.rela.dyn) } :rodata
    .dynamic ALIGN(8) : { *(.dynamic) } :rodata :dynamic
    .data ALIGN(4K) : { *(.got .got.*) *(.data .data.*) } :data
    .bss ALIGN(4K) (NOLOAD) :
    {
        *(.dynbss .dynbss.*)
        *(.bss .bss.*)
        *(COMMON)
    } :data

    /DISCARD/ :
    {
        *(.eh_frame*)
        *(.comment*)
        *(.note*)
        *(.gnu.hash*)
        *(.rel*)
    }
}
