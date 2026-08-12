ENTRY(kernel_entry)

SECTIONS
{
    . = 0x100000;
    __kernel_start = .;

    . = ALIGN(4096);
    __text_start = .;
    .text :
    {
        KEEP(*(.text.kernel_entry))
        *(.text .text.*)
    }
    . = ALIGN(4096);
    __text_end = .;

    __rodata_start = .;
    .rodata :
    {
        *(.rodata .rodata.*)
    }
    . = ALIGN(4096);
    __rodata_end = .;

    __data_start = .;
    .data :
    {
        *(.data .data.*)
        *(.got .got.*)
    }
    . = ALIGN(4096);
    __data_end = .;

    __bss_start = .;
    .bss (NOLOAD) :
    {
        *(.bss .bss.*)
        *(COMMON)
    }
    . = ALIGN(4096);
    __bss_end = .;
    __kernel_end = .;

    /DISCARD/ :
    {
        *(.comment)
        *(.eh_frame .eh_frame_hdr)
    }
}
