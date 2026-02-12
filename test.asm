BITS 16
ORG 0x7C00

start:

    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x7C00
    sti

    mov ah, 0x00
    mov al, 0x03
    int 0x10

    mov eax, 0xE820
    mov edx, 0x534D4150
    mov ecx, 24
    int 0x15

    in al, 0x92
    or al, 2
    out 0x92, al

    mov ax, 0x2401
    int 0x15

    mov dl, 0x80
    mov si, dap
    mov ah, 0x42
    int 0x13

    lgdt [gdt_desc]

    lidt [idt_desc]

    mov eax, cr0
    or eax, 1
    mov cr0, eax
    jmp 0x08:pmode_entry

BITS 32
pmode_entry:

    mov eax, 0x100000
    mov cr3, eax
    mov eax, cr0
    or eax, 0x80000000
    mov cr0, eax

    mov eax, cr4
    or eax, 0x20
    mov cr4, eax

    mov ecx, 0xC0000080
    rdmsr
    or eax, 0x100
    wrmsr
    jmp 0x18:long_entry

BITS 64
long_entry:
    hlt
    jmp long_entry

ALIGN 8

dap:
    db 0x10
    db 0x00
    dw 0x0001
    dw 0x0000
    dw 0x8000
    dq 0x0000000000000002

gdt_start:
    dq 0x0000000000000000
    dq 0x00CF9A000000FFFF
    dq 0x00CF92000000FFFF
    dq 0x00AF9A000000FFFF
gdt_end:

gdt_desc:
    dw gdt_end - gdt_start - 1
    dd gdt_start

idt_desc:
    dw 0
    dd 0

ALIGN 4
multiboot_header:
    dd 0x1BADB002
    dd 0x00000003
    dd -(0x1BADB002 + 0x00000003)

ALIGN 8
multiboot2_header:
    dd 0xE85250D6
    dd 0
    dd multiboot2_end - multiboot2_header
    dd -(0xE85250D6 + 0 + (multiboot2_end - multiboot2_header))

    dw 0
    dw 0
    dd 8
multiboot2_end:

ALIGN 4
pe_image:
    db 'M', 'Z'
    times 58 db 0
    dd pe_sig - pe_image
    times 24 db 0
pe_sig:
    db 'P', 'E', 0, 0
    dw 0x8664
    dw 3
    dd 0
    dd 0
    dd 0
    dw 0xF0
    dw 0x22

    dw 0x20B
    db 0, 0
    dd 0x1000
    dd 0
    dd 0
    dd 0x1000

ALIGN 4
efi_loaded_image_guid:
    dd 0x5B1B31A1
    dw 0x9562
    dw 0x11D2
    db 0x8E, 0x3F, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B

ALIGN 4
efi_gop_guid:
    dd 0x9042A9DE
    dw 0x23DC
    dw 0x4A38
    db 0x96, 0xFB, 0x7A, 0xDE, 0xD0, 0x80, 0x51, 0x6A

times 510-($-$$) db 0
dw 0xAA55
