# Description

NetRipper is a post exploitation tool targeting Windows systems which uses API hooking in order to intercept network traffic and encryption related functions from a low privileged user, being able to capture both plain-text traffic and encrypted traffic before encryption/after decryption. 

NetRipper was released at Defcon 23, Las Vegas, Nevada.

# Legal disclaimer

Usage of NetRipper for attacking targets without prior mutual consent is illegal. It is the end user's responsability to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program!

# Abstract

The post-exploitation activities in a penetration test can be challenging if the tester has low-privileges on a fully patched, well configured Windows machine. This work presents a technique for helping the tester to find useful information by sniffing network traffic of the applications on the compromised machine, despite his low-privileged rights. Furthermore, the encrypted traffic is also captured before being sent to the encryption layer, thus all traffic (clear-text and encrypted) can be sniffed. The implementation of this technique is a tool called NetRipper which uses API hooking to do the actions mentioned above and which has been especially designed to be used in penetration tests, but the concept can also be used to monitor network traffic of employees or to analyze a malicious application.

# Tested applications

NetRipper should be able to capture network traffic from: Putty, WinSCP, SQL Server Management Studio, Microsoft Outlook, Google Chrome, Mozilla Firefox and multiple other tools. The list is not limited to these applications but other tools may require special support.

# Components

```
NetRipper.exe - Configures and inject the DLL  
DLL.dll       - Injected DLL, hook APIs and save data to files  
netripper.rb  - Metasploit post-exploitation module
```

# Binaries 
An automatic build on AppVeyor is available. Binaries can be downloaded from the Artifacts section [here](https://ci.appveyor.com/project/NytroRST/netripper/build/artifacts).

# Command line

```
Injection: NetRipper.exe DLLpath.dll processname.exe  
Example:   NetRipper.exe DLL.dll firefox.exe  

Generate DLL:

  -h,  --help          Print this help message  
  -w,  --write         Full path for the DLL to write the configuration data  
  -l,  --location      Full path where to save data files (default TEMP)  

Plugins:

  -p,  --plaintext     Capture only plain-text data. E.g. true  
  -d,  --datalimit     Limit capture size per request. E.g. 4096  
  -s,  --stringfinder  Find specific strings. E.g. user,pass,config  

Example: NetRipper.exe -w DLL.dll -l TEMP -p true -d 4096 -s user,pass  
```

# Metasploit module

```
msf exploit(multi/handler) > use post/windows/gather/netripper/netripper 
msf post(windows/gather/netripper/netripper) > show options

Module options (post/windows/gather/netripper/netripper):

   Name          Current Setting  Required  Description
   ----          ---------------  --------  -----------
   DATALIMIT     65535            no        The number of bytes to save from requests/responses
   DATAPATH      TEMP             no        Where to save files. E.g. C:\Windows\Temp or TEMP
   DLLPATH                        no        Where to find NetRipper DLLs. Default is /usr/share/metasploit-framework...
   PLAINTEXT     false            no        True to save only plain-text data
   PROCESSIDS                     no        Process IDs. E.g. 1244,1256
   PROCESSNAMES                   no        Process names. E.g. firefox.exe,chrome.exe
   SESSION                        yes       The session to run this module on.
   STRINGFINDER  DEFAULT          no        Search for specific strings in captured data

```

Set PROCESSNAMES or PROCESSIDS and run.

# Metasploit installation (Kali)

1. mkdir /usr/share/metasploit-framework/modules/post/windows/gather/netripper
2. cp Metasploit/netripper.rb /usr/share/metasploit-framework/modules/post/windows/gather/netripper/netripper.rb
3. cp x86/DLL.x86.dll /usr/share/metasploit-framework/modules/post/windows/gather/netripper/DLL.x86.dll
4. cp x64/DLL.x64.dll /usr/share/metasploit-framework/modules/post/windows/gather/netripper/DLL.x64.dll

# Metasploit installation (Backbox)

1. mkdir /opt/metasploit-framework/modules/post/windows/gather/netripper
2. cp Metasploit/netripper.rb /opt/metasploit-framework/modules/post/windows/gather/netripper/netripper.rb
3. cp x86/DLL.x86.dll /opt/metasploit-framework/modules/post/windows/gather/netripper/DLL.x86.dll
4. cp x64/DLL.x64.dll /opt/metasploit-framework/modules/post/windows/gather/netripper/DLL.x64.dll

# PowerShell module

@HarmJ0y Added Invoke-NetRipper.ps1 PowerShell implementation of NetRipper.exe
Please note that the PowerShell module is not up to date.

# Plugins

1. PlainText - Allows to capture only plain-text data
2. DataLimit - Save only first bytes of requests and responses
3. StringFinder - Find specific string in network traffic

# More details

You can find the changelog in the "Changelog.md" file and compilation instructions in the "Compilation.md" file.

NetRipper uses 
- Reflective DLL Injection (https://github.com/stephenfewer/ReflectiveDLLInjection) from Stephen Fewer 
- minhook library (https://github.com/TsudaKageyu/minhook) from Tsuda Kageyu.

# Author

Ionut Popescu (@NytroRST)
