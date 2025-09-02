; Bootloader entry point for MakopaOS
; This code prints 'MAKOPA' to the screen using BIOS interrupt 0x10

ORG 0                     ; Set code origin to 0x7C00 (where BIOS loads the boot sector)
BITS 16                   ; 16-bit real mode (8086 compatible)

start:
    cli                   ; Disable interrupts during setup for safety
    mov ax, 0x7c0         ; Set segment registers to 0x7C00 (boot sector load address >> 4)
    mov ds, ax            ; Data Segment (DS) points to bootloader code/data
    mov es, ax            ; Extra Segment (ES) also points to bootloader
    mov ax, 0x00          ; Stack Segment (SS) set to 0x0000
    mov ss, ax            ; Set SS to 0x0000
    mov sp, 0x7c00        ; Set Stack Pointer (SP) to 0x7C00 (top of boot sector)
    sti                   ; Re-enable interrupts after setup
    
    mov si, message       ; Load address of message string into SI for printing

print_char:
    mov ah, 0eh           ; BIOS teletype output function (int 0x10, ah=0Eh)
    lodsb                 ; Load byte at [SI] into AL, increment SI
    cmp al, 0             ; Check if end of string (null terminator)
    je hang               ; If zero, jump to hang (infinite loop)
    int 0x10              ; Print character in AL to screen
    jmp print_char        ; Repeat for next character

hang:
    jmp hang              ; Infinite loop to halt execution (system halt)

message db 'MAKOPA', 0    ; Message string, null-terminated

times 510-($ - $$) db 0   ; Pad the rest of the sector with zeros to make 512 bytes

; Boot sector signature (must be 0xAA55 for BIOS to recognize as bootable)
dw 0xAA55