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
    .arach.dynstr ALIGN(8) :
    {
        BYTE(0x00)
        BYTE(0x6c) BYTE(0x69) BYTE(0x62) BYTE(0x61) BYTE(0x72)
        BYTE(0x61) BYTE(0x63) BYTE(0x68) BYTE(0x2d) BYTE(0x70)
        BYTE(0x72) BYTE(0x6f) BYTE(0x62) BYTE(0x65) BYTE(0x2e)
        BYTE(0x73) BYTE(0x6f) BYTE(0x00)
    } :rodata
    .dynamic ALIGN(8) :
    {
        QUAD(1) QUAD(1)
        QUAD(5) QUAD(ADDR(.arach.dynstr))
        QUAD(10) QUAD(SIZEOF(.arach.dynstr))
        QUAD(0) QUAD(0)
    } :rodata :dynamic
    .data ALIGN(4K) : { *(.got .got.*) *(.data .data.*) } :data
    .bss ALIGN(4K) (NOLOAD) : { *(.bss .bss.*) *(COMMON) } :data

    /DISCARD/ :
    {
        *(.eh_frame*)
        *(.comment*)
        *(.note*)
        *(.dynamic*)
        *(.dynsym*)
        *(.dynstr*)
        *(.hash*)
        *(.gnu.hash*)
        *(.rela*)
        *(.rel*)
    }
}
