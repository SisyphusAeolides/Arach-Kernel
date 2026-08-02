PHDRS
{
    text PT_LOAD FILEHDR PHDRS FLAGS(5);
    rodata PT_LOAD FLAGS(4);
    data PT_LOAD FLAGS(6);
    dynamic PT_DYNAMIC FLAGS(4);
}

SECTIONS
{
    . = SIZEOF_HEADERS;
    .text : { *(.text .text.*) } :text

    . = ALIGN(4K);
    .rodata : { *(.rodata .rodata.*) } :rodata
    .hash : { *(.hash) } :rodata
    .dynsym : { *(.dynsym) } :rodata
    .dynstr : { *(.dynstr) } :rodata
    .gnu.version : { *(.gnu.version) } :rodata
    .gnu.version_d : { *(.gnu.version_d) } :rodata
    .gnu.version_r : { *(.gnu.version_r) } :rodata
    .relr.dyn : { *(.relr.dyn) } :rodata
    .rela.dyn : { *(.rela.dyn) } :rodata
    .dynamic : { *(.dynamic) } :rodata :dynamic

    . = ALIGN(4K);
    .data :
    {
        *(.data.rel.ro .data.rel.ro.*)
        *(.got .got.*)
        *(.data .data.*)
    } :data
    .init_array :
    {
        KEEP(*(SORT_BY_INIT_PRIORITY(.init_array.*)))
        KEEP(*(.init_array))
    } :data
    .bss (NOLOAD) : { *(.bss .bss.*) *(COMMON) } :data

    /DISCARD/ :
    {
        *(.comment*)
        *(.eh_frame*)
        *(.note*)
        *(.gnu.hash*)
        *(.rela.plt*)
        *(.plt*)
    }
}
