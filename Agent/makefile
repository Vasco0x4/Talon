MAKEFLAGS += -s

NAME	  = demon

CCX86 	  = i686-w64-mingw32-gcc
CCX64 	  = x86_64-w64-mingw32-gcc

CFLAGS	  =  -Os -fno-asynchronous-unwind-tables -masm=intel
CFLAGS	  += -fno-ident -fpack-struct=8 -falign-functions=1
CFLAGS    += -s -ffunction-sections -fdata-sections -fno-exceptions -falign-jumps=1 -w
CFLAGS	  += -falign-labels=1
# -nostartfiles: drop crt2.o (WinMainCRTStartup pulls the whole msvcrt CRT-init
# import chain even when unused); entry is our own WinMain via -e.
# -fno-builtin-strlen: stop GCC from recognising the StrLenA counting loop as a
# strlen call (it would add an orphan msvcrt.dll import).
CFLAGS	  += -nostartfiles -fno-builtin-strlen
CFLAGS	  += -Wl,-s,--no-seh,--gc-sections,--enable-stdcall-fixup
CFLAGS	  += -e WinMain

# make DEBUG=1  -> console diagnostics (links stdio)
ifdef DEBUG
CFLAGS   += -DTALON_DEBUG=1
endif

INCLUDE	  += -I Include
LINKING	  += -l netapi32 -l ws2_32 -l wsock32 -l wtsapi32 -l crypt32 -l shlwapi -l ntdll -l user32 -l gdi32 -l netapi32 -l iphlpapi -l winhttp
SOURCE 	  =  $(wildcard Source/*)


all:
	printf "\033[0;36m[*]\033[0m Building Talon agent...\n"

	# TODO: remove exe. lasting is going to be Dll and Reflective Dll
	$(CCX64) $(SOURCE) $(INCLUDE) $(CFLAGS) $(LINKING) -m64 -o Bin/Talon.exe

	printf "\033[0;36m[*]\033[0m Finished building Talon payload\n"