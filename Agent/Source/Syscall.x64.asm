[bits 64]

; SysInvoke( arg1 in rcx, arg2 in rdx, PSYS_CONFIG in r8 )
;
; Tail-jumps to ntdll's own `syscall` instruction (resolved at runtime by
; SysExtract), so no 0F 05 bytes live in our .text. The stub's `ret` after
; the syscall returns us to the C caller with NTSTATUS in rax.
; Modeled on Demon (Havoc) src/asm/Syscall.x64.asm, simplified: the config
; pointer is passed as an argument instead of a SysSetConfig/r11 global, so
; nothing can clobber it between two calls.

section .text
    global SysInvoke
    SysInvoke:
        mov r10, rcx          ; Win64 syscall ABI: r10 = copy of arg1
        mov eax, [r8 + 8]     ; syscall service number from config
        jmp QWORD [r8]        ; -> ntdll `syscall` instruction
