#ifndef TALON_CORE_H
#define TALON_CORE_H

#define PRINT_HEX( b, l )                               \
    do {                                                \
        Dbg( #b ": [%d] [ ", ( int ) ( l ) );           \
        for ( SIZE_T i = 0 ; i < ( l ); i++ )           \
        {                                               \
            Dbg( "%02x ", ( ( PUCHAR ) b ) [ i ] );     \
        }                                               \
        Dbg( "]" );                                     \
    } while ( 0 )

VOID  TalonInit();
VOID  TalonSleep( VOID );

VOID  AnonPipeRead( HANDLE hSTD_OUT_Read );
ULONG RandomNumber32( VOID );
SIZE_T StrLenA( LPCSTR s );

#endif
