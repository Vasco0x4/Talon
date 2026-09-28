[bits 64]

; Return-address spoofing trampoline. Ported from AceLdr (kyleavery), which is
; what Demon (Havoc) ships:
; https://www.unknowncheats.me/forum/anti-cheat-bypass/268039-x64-return-address-spoofing-source-explanation.html
;
; Called as Spoof( a, b, c, d, &PRM, NULL, e, f, g, h [, i] ):
;   - a..d must already be in rcx/rdx/r8/r9 (Win64 arg 1-4)
;   - &PRM is stack arg 5 ([rsp+0x28]); the NULL in arg 6 pads so that real
;     args e.. land exactly on the target function's own arg5+ slots
;   - PRM = { Trampoline (jmp [rbx] gadget), Function, Rbx }
;
; The target's return address is replaced with the kernel32 gadget; when it
; returns we land in fixup, restore rbx, and resume SpoofRetAddr exactly where
; a normal `ret` would have left it (rsp = post-push + 8).

DEFAULT REL

GLOBAL Spoof

[SECTION .text]
Spoof:
    pop    r11
    add    rsp, 8
    mov    rax, [rsp + 24]
    mov    r10, [rax]
    mov    [rsp], r10
    mov    r10, [rax + 8]
    mov    [rax + 8], r11
    mov    [rax + 16], rbx
    lea    rbx, [fixup]
    mov    [rax], rbx
    mov    rbx, rax
    jmp    r10

fixup:
    sub    rsp, 16
    mov    rcx, rbx
    mov    rbx, [rcx + 16]
    jmp    QWORD [rcx + 8]
