# Abstract

The post-exploitation activities in a penetration test can be challenging if the tester has low-privileges on a fully patched, well configured Windows machine. This work presents a technique for helping the tester to find useful information by sniffing network traffic of the applications on the compromised machine, despite his low-privileged rights. Furthermore, the encrypted traffic is also captured before being sent to the encryption layer, thus all traffic (clear-text and encrypted) can be sniffed. The implementation of this technique is a tool called NetRipper which uses API hooking to do the actions mentioned above and which has been especially designed to be used in penetration tests, but the concept can also be used to monitor network traffic of employees or to analyze a malicious application.

# Components

NetRipper.exe - Configures and inject the DLL  
DLL.dll       - Injected DLL, hook apis and save data to files  
netripper.rb  - Metasploit post-exploitation module  

# Command line

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
