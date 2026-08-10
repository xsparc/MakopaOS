ENTRY(kernel_entry)

SECTIONS
{
    . = 0x100000;

    . = ALIGN(4096);
    .text :
    {
        KEEP(*(.text.kernel_entry))
        *(.text .text.*)
    }

    . = ALIGN(4096);
    .rodata :
    {
        *(.rodata .rodata.*)
    }

    . = ALIGN(4096);
    .data :
    {
        *(.data .data.*)
    }

    . = ALIGN(4096);
    .bss :
    {
        *(.bss .bss.*)
        *(COMMON)
    }

    /DISCARD/ :
    {
        *(.comment)
        *(.eh_frame .eh_frame_hdr)
    }
}
