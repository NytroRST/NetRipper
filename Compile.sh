#!/bin/sh

############################################################
#                                                          #
#       NetRipper - Linux cross-compilation script         #
#             Requires mingw-w64 compiler                  #
#                                                          #
############################################################

# Source code paths

PATH_DLL_SRC="DLL"
PATH_MINHOOK_SRC="minhook"

# Compiler

COMPILER32="i686-w64-mingw32-g++"
COMPILER64="x86_64-w64-mingw32-g++"
ARCHIVER32="i686-w64-mingw32-ar"
ARCHIVER64="x86_64-w64-mingw32-ar"

# Include paths 

INCLUDE_PATH="/usr/share/mingw-w64/include/"
INCLUDE_MINHOOK="$PATH_MINHOOK_SRC/include/"

# Library paths

LIB_PATH32="/usr/i686-w64-mingw32/lib/"
LIB_PATH64="/usr/x86_64-w64-mingw32/lib/"
LIB_MINHOOK="$PATH_MINHOOK_SRC/lib/"

# Output directories

OUTPUT_OBJECTS32="NetRipper_x86_out"
OUTPUT_OBJECTS64="NetRipper_x64_out"
OUTPUT_BINARIES="NetRipper_bin"

# Start script 

echo "- Checking requirements"

# Check if source directories exist

if [ ! -d "$PATH_DLL_SRC" ]; then
	echo "NetRipper DLL source code directory not found: $PATH_DLL_SRC"
	exit 1
fi

if [ ! -d "$PATH_MINHOOK_SRC" ]; then
	echo "MinHook source code directory not found: $PATH_MINHOOK_SRC"
	exit 2
fi

# Check if mingw directories exist

if [ ! -d "$INCLUDE_PATH" ]; then
	echo "MinGW include directory not found: $INCLUDE_PATH"
	exit 3
fi

if [ ! -d "$LIB_PATH32" ]; then
	echo "MinGW 32 bits libraries directory not found: $LIB_PATH32"
	exit 4
fi

if [ ! -d "$LIB_PATH64" ]; then
	echo "MinGW 64 bits libraries directory not found: $LIB_PATH64"
	exit 5
fi

# Check if mingw compilers and archivers are present

if ! [ -x "$(command -v $COMPILER32)" ]; then
	echo "MinGW compiler (32 bits) not found: $COMPILER32"
	exit 6
fi

if ! [ -x "$(command -v $COMPILER64)" ]; then
	echo "MinGW compiler (64 bits) not found: $COMPILER64"
	exit 6
fi

if ! [ -x "$(command -v $ARCHIVER32)" ]; then
	echo "MinGW archiver (32 bits)	not found: $ARCHIVER32"
	exit 6
fi

if ! [ -x "$(command -v $ARCHIVER64)" ]; then
	echo "MinGW archiver (64 bits)	not found: $ARCHIVER64"
	exit 6
fi

# Basic cleanup

echo "- Basic cleanup"

[ -d "$OUTPUT_OBJECTS32" ]  && rm -rf $OUTPUT_OBJECTS32
[ -d "$OUTPUT_OBJECTS64" ]  && rm -rf $OUTPUT_OBJECTS64
[ -d "$OUTPUT_BINARIES" ] && rm -rf $OUTPUT_BINARIES

[ -f "$PATH_MINHOOK_SRC/lib/libMinHook.x86.a" ] && rm -f $PATH_MINHOOK_SRC/lib/libMinHook.x86.a
[ -f "$PATH_MINHOOK_SRC/lib/libMinHook.x64.a" ] && rm -f $PATH_MINHOOK_SRC/lib/libMinHook.x64.a

# Create output directories

echo "- Creating output directories"

mkdir -p $OUTPUT_OBJECTS32
mkdir -p $OUTPUT_OBJECTS64
mkdir -p $OUTPUT_BINARIES

# Compile MinHook library - 32 bits

echo "- Compiling MinHook library (32 bits)"

$COMPILER32 -c -I$PATH_MINHOOK_SRC/include -o $OUTPUT_OBJECTS32/buffer.o $PATH_MINHOOK_SRC/src/buffer.c
$COMPILER32 -c -I$PATH_MINHOOK_SRC/include -o $OUTPUT_OBJECTS32/hook.o $PATH_MINHOOK_SRC/src/hook.c 
$COMPILER32 -c -I$PATH_MINHOOK_SRC/include -o $OUTPUT_OBJECTS32/trampoline.o $PATH_MINHOOK_SRC/src/trampoline.c 

$COMPILER32 -c -I$PATH_MINHOOK_SRC/include -o $OUTPUT_OBJECTS32/hde32.o $PATH_MINHOOK_SRC/src/hde/hde32.c
$COMPILER32 -c -I$PATH_MINHOOK_SRC/include -o $OUTPUT_OBJECTS32/hde64.o $PATH_MINHOOK_SRC/src/hde/hde64.c 

echo "- Archiving MinHook library (32 bits)"

$ARCHIVER32 rcs $PATH_MINHOOK_SRC/lib/libMinHook.x86.a $OUTPUT_OBJECTS32/*.o

# Compile MinHook library - 64 bits

echo "- Compiling MinHook library (64 bits)"

$COMPILER64 -c -I$PATH_MINHOOK_SRC/include -o $OUTPUT_OBJECTS64/buffer.o $PATH_MINHOOK_SRC/src/buffer.c
$COMPILER64 -c -I$PATH_MINHOOK_SRC/include -o $OUTPUT_OBJECTS64/hook.o $PATH_MINHOOK_SRC/src/hook.c 
$COMPILER64 -c -I$PATH_MINHOOK_SRC/include -o $OUTPUT_OBJECTS64/trampoline.o $PATH_MINHOOK_SRC/src/trampoline.c 

$COMPILER64 -c -I$PATH_MINHOOK_SRC/include -o $OUTPUT_OBJECTS64/hde32.o $PATH_MINHOOK_SRC/src/hde/hde32.c
$COMPILER64 -c -I$PATH_MINHOOK_SRC/include -o $OUTPUT_OBJECTS64/hde64.o $PATH_MINHOOK_SRC/src/hde/hde64.c 

echo "- Archiving MinHook library (64 bits)"

$ARCHIVER64 rcs $PATH_MINHOOK_SRC/lib/libMinHook.x64.a $OUTPUT_OBJECTS64/*.o

# Compile NetRipper DLL - 32 bits 

echo "- Compiling NetRipper DLL (32 bits)"

$COMPILER32 -c -I$INCLUDE_PATH -I$INCLUDE_MINHOOK -o $OUTPUT_OBJECTS32/stdafx.o $PATH_DLL_SRC/stdafx.cpp 
$COMPILER32 -c -I$INCLUDE_PATH -I$INCLUDE_MINHOOK -o $OUTPUT_OBJECTS32/DebugLog.o $PATH_DLL_SRC/DebugLog.cpp 
$COMPILER32 -c -I$INCLUDE_PATH -I$INCLUDE_MINHOOK -o $OUTPUT_OBJECTS32/DynConfig.o $PATH_DLL_SRC/DynConfig.cpp 
$COMPILER32 -c -I$INCLUDE_PATH -I$INCLUDE_MINHOOK -o $OUTPUT_OBJECTS32/FunctionFlow.o $PATH_DLL_SRC/FunctionFlow.cpp 
$COMPILER32 -c -I$INCLUDE_PATH -I$INCLUDE_MINHOOK -o $OUTPUT_OBJECTS32/HookedFunctions.o $PATH_DLL_SRC/HookedFunctions.cpp -masm=intel
$COMPILER32 -c -I$INCLUDE_PATH -I$INCLUDE_MINHOOK -o $OUTPUT_OBJECTS32/InjectedDLL.o $PATH_DLL_SRC/InjectedDLL.cpp 
$COMPILER32 -c -I$INCLUDE_PATH -I$INCLUDE_MINHOOK -o $OUTPUT_OBJECTS32/NonExportedHooks.o $PATH_DLL_SRC/NonExportedHooks.cpp 
$COMPILER32 -c -I$INCLUDE_PATH -I$INCLUDE_MINHOOK -o $OUTPUT_OBJECTS32/PCAP.o $PATH_DLL_SRC/PCAP.cpp 
$COMPILER32 -c -I$INCLUDE_PATH -I$INCLUDE_MINHOOK -o $OUTPUT_OBJECTS32/Plugin.o $PATH_DLL_SRC/Plugin.cpp 
$COMPILER32 -c -I$INCLUDE_PATH -I$INCLUDE_MINHOOK -o $OUTPUT_OBJECTS32/PluginSystem.o $PATH_DLL_SRC/PluginSystem.cpp 
$COMPILER32 -c -I$INCLUDE_PATH -I$INCLUDE_MINHOOK -o $OUTPUT_OBJECTS32/Process.o $PATH_DLL_SRC/Process.cpp 
$COMPILER32 -c -I$INCLUDE_PATH -I$INCLUDE_MINHOOK -o $OUTPUT_OBJECTS32/ReflectiveLoader.o $PATH_DLL_SRC/ReflectiveLoader.cpp 
$COMPILER32 -c -I$INCLUDE_PATH -I$INCLUDE_MINHOOK -o $OUTPUT_OBJECTS32/Utils.o $PATH_DLL_SRC/Utils.cpp 
$COMPILER32 -c -I$INCLUDE_PATH -I$INCLUDE_MINHOOK -o $OUTPUT_OBJECTS32/dllmain.o $PATH_DLL_SRC/dllmain.cpp 

echo "- Linking NetRipper DLL (32 bits)"

$COMPILER32 -o $OUTPUT_BINARIES/DLL.x86.dll -shared $OUTPUT_OBJECTS32/*.o -L$LIB_MINHOOK -lMinHook.x86 -lws2_32 -L$LIB_PATH32 -lmsvcrt -static

# Compile NetRipper DLL - 64 bits 

echo "- Compiling NetRipper DLL (64 bits)"

$COMPILER64 -c -I$INCLUDE_PATH -I$INCLUDE_MINHOOK -o $OUTPUT_OBJECTS64/stdafx.o $PATH_DLL_SRC/stdafx.cpp 
$COMPILER64 -c -I$INCLUDE_PATH -I$INCLUDE_MINHOOK -o $OUTPUT_OBJECTS64/DebugLog.o $PATH_DLL_SRC/DebugLog.cpp 
$COMPILER64 -c -I$INCLUDE_PATH -I$INCLUDE_MINHOOK -o $OUTPUT_OBJECTS64/DynConfig.o $PATH_DLL_SRC/DynConfig.cpp 
$COMPILER64 -c -I$INCLUDE_PATH -I$INCLUDE_MINHOOK -o $OUTPUT_OBJECTS64/FunctionFlow.o $PATH_DLL_SRC/FunctionFlow.cpp 
$COMPILER64 -c -I$INCLUDE_PATH -I$INCLUDE_MINHOOK -o $OUTPUT_OBJECTS64/HookedFunctions.o $PATH_DLL_SRC/HookedFunctions.cpp 
$COMPILER64 -c -I$INCLUDE_PATH -I$INCLUDE_MINHOOK -o $OUTPUT_OBJECTS64/InjectedDLL.o $PATH_DLL_SRC/InjectedDLL.cpp 
$COMPILER64 -c -I$INCLUDE_PATH -I$INCLUDE_MINHOOK -o $OUTPUT_OBJECTS64/NonExportedHooks.o $PATH_DLL_SRC/NonExportedHooks.cpp 
$COMPILER64 -c -I$INCLUDE_PATH -I$INCLUDE_MINHOOK -o $OUTPUT_OBJECTS64/PCAP.o $PATH_DLL_SRC/PCAP.cpp 
$COMPILER64 -c -I$INCLUDE_PATH -I$INCLUDE_MINHOOK -o $OUTPUT_OBJECTS64/Plugin.o $PATH_DLL_SRC/Plugin.cpp 
$COMPILER64 -c -I$INCLUDE_PATH -I$INCLUDE_MINHOOK -o $OUTPUT_OBJECTS64/PluginSystem.o $PATH_DLL_SRC/PluginSystem.cpp 
$COMPILER64 -c -I$INCLUDE_PATH -I$INCLUDE_MINHOOK -o $OUTPUT_OBJECTS64/Process.o $PATH_DLL_SRC/Process.cpp 
$COMPILER64 -c -I$INCLUDE_PATH -I$INCLUDE_MINHOOK -o $OUTPUT_OBJECTS64/ReflectiveLoader.o $PATH_DLL_SRC/ReflectiveLoader.cpp 
$COMPILER64 -c -I$INCLUDE_PATH -I$INCLUDE_MINHOOK -o $OUTPUT_OBJECTS64/Utils.o $PATH_DLL_SRC/Utils.cpp 
$COMPILER64 -c -I$INCLUDE_PATH -I$INCLUDE_MINHOOK -o $OUTPUT_OBJECTS64/dllmain.o $PATH_DLL_SRC/dllmain.cpp 

echo "- Linking NetRipper DLL (64 bits)"

$COMPILER64 -o $OUTPUT_BINARIES/DLL.x64.dll -shared $OUTPUT_OBJECTS64/*.o -L$LIB_MINHOOK -lMinHook.x64 -lws2_32 -L$LIB_PATH64 -lmsvcrt -static

# Check results

if [ -f "$OUTPUT_BINARIES/DLL.x86.dll" ]; then
	echo "NetRipper DLL (32 bits) successfully compiled: $OUTPUT_BINARIES/DLL.x86.dll"
else 
	echo "Error compiling NetRipper DLL (32 bits)"
fi

if [ -f "$OUTPUT_BINARIES/DLL.x64.dll" ]; then
	echo "NetRipper DLL (64 bits) successfully compiled: $OUTPUT_BINARIES/DLL.x64.dll"
else 
	echo "Error compiling NetRipper DLL (64 bits)"
fi
