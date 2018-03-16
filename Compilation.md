# Compilation

In order to compile NetRipper, the following steps are required:
1. Compile minhook library
2. Compile NetRipper 

NetRipper and minhook are compiled using Visual Studio 15.6.x (latest version).

# minhook compilation

1. Open solution from minhook\build\VC15\MinHookVC15.sln
2. It might be required to install Visual Studio Platform Toolset for Windows XP
3. Select Release configuration and Build for Win32
4. Select Release configuration and Build for x64
5. Copy the compiled libraries from minhook\build\VC15\lib\Release to minhook\lib

# NetRipper compilation

1. Open the NetRipper.sln solution
2. It might be required to change the Windows SDK version from each project (DLL and NetRipper) settings
3. Build for x86
4. Build for x64 
5. You can find 32 bits binaries in x86 directory (DLL.x86.dll and NetRipper.x86.exe) 
6. You can find 64 bits binaries in x64 directory (DLL.x64.dll and NetRipper.x64.exe) 
