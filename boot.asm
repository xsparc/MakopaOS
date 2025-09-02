; Bootloader entry point for MakopaOS
; This code prints 'MAKOPA' to the screen using BIOS interrupt 0x10

ORG 0x7c00                ; Set code origin to 0x7C00 (where BIOS loads the boot sector)
BITS 16                   ; 16-bit real mode

start:
    mov si, message       ; SI points to the start of the message string

print_char:
    mov ah, 0eh           ; BIOS teletype function (int 0x10, ah=0Eh)
    lodsb                 ; Load byte at [SI] into AL, increment SI
    cmp al, 0             ; Check if end of string (null terminator)
    je hang               ; If zero, jump to hang (infinite loop)
    int 0x10              ; Print character in AL to screen
    jmp print_char        ; Repeat for next character

hang:
    jmp hang              ; Infinite loop to halt execution

message db 'MAKOPA', 0    ; Message string, null-terminated

times 510-($ - $$) db 0   ; Pad the rest of the sector with zeros
dw 0xAA55                 ; Boot sector signature (must be 0xAA55)