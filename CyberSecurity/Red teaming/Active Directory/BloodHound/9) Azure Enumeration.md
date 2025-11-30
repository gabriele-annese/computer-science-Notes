We've learned how to use BloodHound to identify misconfigurations in Active Directory environments, but in this section, we'll focus on Azure and how we can use BloodHound to identify attack paths and potential weaknesses in the Azure environment.

While the main focus of this section will be on the offensive usage of BloodHound in Azure, it's important to note that both Red and Blue Teams can benefit from this tool. Red Teams can use the information gathered by BloodHound to identify attack paths, and Blue Teams to prioritize remediation efforts and secure their Azure environment. BloodHound provides valuable insights into the security of Azure environments, whether for offensive or defensive purposes.

## Overview AzureHound

Just as we discussed attacks on Active Directory environments and the different components that BloodHound includes to allow us to identify attack paths, in the same way, we can use BloodHound to identify Attack paths in Azure.

The approach to identify attacks and abuse edges are similar to Active Directory. For Azure, we will have nodes and edges that start with `Az` exclusive to the Microsoft cloud.

The nodes available in BloodHound version 4.2 are the following:

|Node|Description|
|---|---|
|[AZTenant](https://bloodhound.readthedocs.io/en/latest/data-analysis/nodes.html#aztenant)|Represents an Azure AD tenant, which is a dedicated instance of Azure AD that an organization owns and uses to manage access to applications and resources.|
|[AZUser](https://bloodhound.readthedocs.io/en/latest/data-analysis/nodes.html#AzUser)|Represents a user in Azure Active Directory (Azure AD) and contains information about the user such as their email address, display name, and job title.|
|[AZGroup](https://bloodhound.readthedocs.io/en/latest/data-analysis/nodes.html#AzGroup)|Represents a group in Azure AD, which can be used to manage access to resources and applications.|
|[AZApp](https://bloodhound.readthedocs.io/en/latest/data-analysis/nodes.html#AzApp)|Represents an application in Azure AD, which can be used to provide secure access to resources and APIs.|
|[AZSubscription](https://bloodhound.readthedocs.io/en/latest/data-analysis/nodes.html#AzSubscription)|Represents an Azure subscription, which is a logical container for resources in Azure.|
|[AZResourceGroup](https://bloodhound.readthedocs.io/en/latest/data-analysis/nodes.html#AZResourceGroup)|Represents a resource group in Azure, which is a container for resources that share a lifecycle and are managed together.|
|[AZVM](https://bloodhound.readthedocs.io/en/latest/data-analysis/nodes.html#AZVM)|Represents a virtual machine (VM) in Azure, which is a virtualized computing environment used to deploy and run applications.|
|[AZDevice](https://bloodhound.readthedocs.io/en/latest/data-analysis/nodes.html#AZDevice)|Represents a device in Azure AD, which can be used to manage access to resources and applications.|
|[AZServicePrincipal](https://bloodhound.readthedocs.io/en/latest/data-analysis/nodes.html#AZServicePrincipal)|Represents a service principal in Azure AD, which is a security identity used by applications and services to access resources in Azure.|

The edges available in BloodHound version 4.2 are as follows:

|Edge|Description|
|---|---|
|[AZAddMembers](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#azaddmembers)|Indicates that a principal can add members to a group or directory role.|
|[AZAddOwner](https://posts.specterops.io/introducing-bloodhound-4-2-the-azure-refactor-1cff734938bd)|Indicates that a principal can add other users as owners of a subscription or management group.|
|[AZAppAdmin](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#AZAppAdmin)|Indicates that a principal is assigned to an administrative role for an Azure AD application.|
|[AZCloudAppAdmin](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#AZCloudAppAdmin)|Indicates that a principal is assigned to an administrative role for a cloud application.|
|[AZContains](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#AZContains)|Indicates that a group or directory role contains a member.|
|[AZContributor](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#AZContributor)|Indicates that a principal has been assigned the Contributor role at a resource scope, allowing them to manage all resource types within that scope.|
|[AZExecuteCommand](https://posts.specterops.io/introducing-bloodhound-4-2-the-azure-refactor-1cff734938bd)|Indicates that a principal has permission to execute a command on a virtual machine.|
|[AZGetCertificates](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#AZGetCertificates)|Indicates that a principal has permission to retrieve certificates.|
|[AZGetKeys](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#AZGetKeys)|Indicates that a principal has permission to retrieve keys.|
|[AZGetSecrets](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#AZGetSecrets)|Indicates that a principal has permission to retrieve secrets.|
|[AZGlobalAdmin](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#AZGlobalAdmin)|Indicates that a principal is assigned to the Global Administrator role in Azure AD.|
|[AZKeyVaultContributor](https://posts.specterops.io/introducing-bloodhound-4-2-the-azure-refactor-1cff734938bd)|Indicates that a principal has been assigned the Key Vault Contributor role at the resource group or resource level, allowing them to manage key vaults.|
|[AZManagedIdentity](https://posts.specterops.io/introducing-bloodhound-4-2-the-azure-refactor-1cff734938bd)|Indicates that a resource has an associated managed identity, allowing it to authenticate with other Azure services.|
|[AZOwns](https://posts.specterops.io/introducing-bloodhound-4-2-the-azure-refactor-1cff734938bd)|Indicates that a principal owns a resource.|
|[AZPrivilegedRoleAdmin](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#AZPrivilegedRoleAdmin)|Indicates that a principal is assigned to a built-in role that grants full access to Azure AD and all Azure services.|
|[AZResetPassword](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#AZResetPassword)|Allows a user to reset passwords for other users|
|[AZRunAs](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#AZRunAs)|Represents the ability to run as an account, either through a scheduled task, service, or any other impersonation|
|[AZUserAccessAdministrator](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#AZUserAccessAdministrator)|Allows a user to manage user access to Azure resources|
|[AZVMAdminLogin](https://posts.specterops.io/introducing-bloodhound-4-2-the-azure-refactor-1cff734938bd)|Allows a user to log in as a VM administrator|

**Note:** Keep in mind that not all edges are documented. Most of them have different details for their attack path than we had in Active Directory. Cloud environments can change rapidly, and we must keep up to date with the changes as they occur.

For additional information about these nodes, their uses, and definitions, we can refer to the [official BloodHound documentation](https://bloodhound.readthedocs.io/en/latest/index.html).

----

## Creating an Azure Tenant

To practice in an Azure environment, we need to create a tenant with an Azure Subscription. We will use the free version of Azure, which gives us $200 USD for one month. To complete the registration for the free version, we can use the following link: [https://azure.microsoft.com/en-us/free/](https://azure.microsoft.com/en-us/free/). Note that a credit card is required. Additionally, if you are a student, you can use [Azure for Students](https://azure.microsoft.com/en-us/free/students/) with no credit card required.

**Note:** These exercises are optional, but it is recommended that they be performed to familiarize yourself with cloud attacks. To complete these exercises, we will need to create the free Azure account using the link above.

You can follow the process based on the [Azure Free Account](https://azure.microsoft.com/en-us/free/) page. The following example is a reference, but the process may differ for you and the region where you are.

1. Go to the [Azure Free Account](https://azure.microsoft.com/en-us/free/) portal and follow the process starting by clicking on `Start free`.

![Microsoft sign-in page prompting for email, phone, or Skype. Options to create an account or recover access. Background shows people walking in a modern building.](https://academy.hackthebox.com/storage/modules/69/azure_free_account_1.jpg)

2. Create a new account:

![Microsoft sign-in page with fields for email, phone, or Skype. Options to create an account or recover access. Background shows people in a modern building.](https://academy.hackthebox.com/storage/modules/69/azure_free_account_2.jpg)

3. We can use an existing email or create a new one. For this exercise, we will use an already existing email.

![Microsoft create account page with email field filled. Options to use a phone number or get a new email address. Background shows people in a modern building.](https://academy.hackthebox.com/storage/modules/69/azure_free_account_3.jpg)

4. Set a Password:

![Microsoft create a password page for an email account. Password field with option to show password. Background shows people in a modern building.](https://academy.hackthebox.com/storage/modules/69/azure_free_account_4.jpg)

5. We will receive a confirmation email to verify our identity:

![Email from Microsoft account team to verify email address with security code 2325. Instructions to use the code to finish setting up the account.](https://academy.hackthebox.com/storage/modules/69/azure_free_account_5.jpg)

6. Use the code you receive to verify your email:

![Microsoft verify email page for plaintexthackthebox@gmail.com. Enter code 2325. Option to receive information about Microsoft products. Background shows people in a modern building.](https://academy.hackthebox.com/storage/modules/69/azure_free_account_6.jpg)

7. Complete the puzzle:

![Microsoft create account page for plaintexthackthebox@gmail.com. Prompt to solve a puzzle to verify not a robot. Audio option available. Background shows people in a modern building.](https://academy.hackthebox.com/storage/modules/69/azure_free_account_7.jpg)

8. Add your information:

![Azure sign-up page for a free account. Form fields for country (Dominican Republic), name, email, and phone. Benefits include 12 months free services, 55+ services always free, and $200 credit. No automatic charges.](https://academy.hackthebox.com/storage/modules/69/azure_free_account_8.jpg)

9. Verify your phone:

![Verification code input field with code 726697 entered. Buttons for 'Verify code' and 'I did not receive a code'.](https://academy.hackthebox.com/storage/modules/69/azure_free_account_9.jpg)

10. Add the credit card information and complete the process.

![Azure sign-up page for identity verification by card. Fields for cardholder name, card number, expiration date, CVV, and address. Accepts Visa, American Express, and Mastercard. Benefits include 12 months free services, 55+ services always free, and $200 credit. No automatic charges.](https://academy.hackthebox.com/storage/modules/69/azure_free_account_10.jpg)

**Note:** If you had an error while registering, it could be for multiple reasons. One of the most common is that you had already used Azure Free.

You could use Pay-As-You-Go to complete the exercise. The average cost will be around ~5.00 USD if you use it for a week. However, you will have to manually delete the created resources and cancel your subscription so that it does not generate additional costs.

Complete the registration process and visit the [Azure Portal](https://portal.azure.com/).

![Microsoft Azure welcome page offering options: Start with a free trial ($200 credit, 12 months free services), Manage Azure Active Directory, and Access student benefits. Buttons for Start, View, and Explore.](https://academy.hackthebox.com/storage/modules/69/azure_free_account_11.jpg)

## Using TheEdgeMaker

Once we have created our Azure account and subscription, we can use [TheEdgeMaker](https://github.com/juliourena/TheEdgeMaker). A PowerShell script that allows us to create Azure Edges for use in BloodHound automatically.

**Note:** By using this Script, we are creating weak configurations in Azure to perform the practices. Make sure to use it in a controlled environment. It is not recommended for use in production, development, or an environment not created for this purpose.

1. Connect to the target machine and run PowerShell as Administrator and execute the Script:

#### Execute TheEdgeMaker

```powershell-session
PS C:\Tools\TheEdgeMaker> .\TheEdgeMaker.ps1
```

#### Login with the Azure Account we created

![Microsoft Azure sign-in window for plaintexthackthebox@gmail.com. Options to create an account or recover access. Buttons for Back and Next. Background shows Windows PowerShell.](https://academy.hackthebox.com/storage/modules/69/azurehound_login.jpg)

#### Execute TheEdgeMaker

```powershell
PS C:\Tools\TheEdgeMaker> .\TheEdgeMaker.ps1

Account                       SubscriptionName     TenantId                             Environment
-------                       ----------------     --------                             -----------
plaintexthackthebox@gmail.com Azure subscription 1 92e13faa-6af8-4501-80b9-421271bc3e38 AzureCloud

Name               : Azure subscription 1 (4c30dd8a-ea98-4d0b-bb15-86f011cafc17) -
                     92e13faa-6af8-4501-80b9-421271bc3e38 - plaintexthackthebox@gmail.com
Account            : plaintexthackthebox@gmail.com
Environment        : AzureCloud
Subscription       : 4c30dd8a-ea98-4d0b-bb15-86f011cafc17
Tenant             : 92e13faa-6af8-4501-80b9-421271bc3e38
TokenCache         :
VersionProfile     :
ExtendedProperties : {}


## Tenant Information
Tenant: plaintexthacktheboxgmail.onmicrosoft.com

The current location is 'East US'. Do you want to change it? (Y/N): N
...SNIP...
```

The output includes the tenant name, in this case: `plaintexthacktheboxgmail.onmicrosoft.com`. We will need this information when to run AzureHound. Make sure to take note of your tenant name.

The Script stops to inform us which is the location of the resources we will create in Azure. By default, it uses `East US`. We will keep this location by pressing `N`.

  Azure Enumeration

```powershell
PS C:\Tools\TheEdgeMaker> .\TheEdgeMaker.ps1
...SNIP...

## The current location is 'East US'.

## Creating Users
[+] AAD Account Created Successfully - Emily Smith
[+] AAD Account Created Successfully - Madison Johnson
[+] AAD Account Created Successfully - Avery Williams
[+] AAD Account Created Successfully - Sophia Jones
[+] AAD Account Created Successfully - Olivia Brown
[+] AAD Account Created Successfully - Abigail Davis
[+] AAD Account Created Successfully - Isabella Miller
[+] AAD Account Created Successfully - Mia Wilson
[+] AAD Account Created Successfully - Charlotte Moore
[+] AAD Account Created Successfully - Ava Taylor

## Creating Resource Group

ResourceGroupName : RG-KeyVault
Location          : eastus
ProvisioningState : Succeeded
Tags              :
TagsTable         :
ResourceId        : /subscriptions/4c30dd8a-ea98-4d0b-bb15-86f011cafc17/resourceGroups/RG-KeyVault
ManagedBy         :

[+] Resource group 'RG-KeyVault' created successfully in East US.

...SNIP...
```

Once it is finished, we are ready to execute AzureHound.

## Using AzureHound

AzureHound is a Go binary that collects data from AzureAD and AzureRM via the MS Graph and Azure REST APIs. It does not use external dependencies and will run on any operating system. We can build [AzureHound](https://github.com/BloodHoundAD/AzureHound) from the source or download it from their [github repository](https://github.com/BloodHoundAD/AzureHound/releases). AzureHound is in the `C:\Tools` directory in the target machine.

There are several authentication methods for AzureHound:

- Username and Password
- JSON Web Token (JWT)
- Refresh Token
- Service Principal Secret
- Service Principal Certificate

For this exercise, we will use a username and password. To learn more about other methods, please visit [AzureHound official documentation](https://bloodhound.readthedocs.io/en/latest/data-collection/azurehound.html).

We will assume we compromise Isabella Miller's account, and her password is `HacktheboxAcademy01!`. Make sure to replace the domain name `plaintexthacktheboxgmail.onmicrosoft.com` with the corresponding tenant for your environment.

#### Running AzureHound

```powershell
PS C:\Tools> .\azurehound.exe -u "Isabella.Miller@plaintexthacktheboxgmail.onmicrosoft.com" -p "HacktheboxAcademy01!" list --tenant "plaintexthacktheboxgmail.onmicrosoft.com" -o all.json
AzureHound v1.2.3
Created by the BloodHound Enterprise team - https://bloodhoundenterprise.io

No configuration file located at C:\Users\julio\.config\azurehound\config.json
No configuration file located at C:\Users\julio\.config\azurehound\config.json
2023-02-17T11:09:21-06:00 INF collecting azure objects...
2023-02-17T11:09:21-06:00 INF finished listing all groups count=9
2023-02-17T11:09:22-06:00 INF finished listing all subscriptions count=0
2023-02-17T11:09:22-06:00 INF finished listing all key vaults
2023-02-17T11:09:22-06:00 INF finished listing all resource groups
2023-02-17T11:09:22-06:00 INF finished listing all subscription role assignments
2023-02-17T11:09:22-06:00 INF finished listing all subscription user access admins
2023-02-17T11:09:22-06:00 INF finished listing all resource group role assignments
2023-02-17T11:09:22-06:00 INF finished listing all virtual machines
2023-02-17T11:09:22-06:00 INF finished listing all virtual machine role assignments
2023-02-17T11:09:22-06:00 INF finished listing all key vault role assignments
2023-02-17T11:09:22-06:00 INF finished listing all devices count=0
2023-02-17T11:09:22-06:00 INF finished listing all device owners
2023-02-17T11:09:22-06:00 INF finished listing all users count=11
2023-02-17T11:09:22-06:00 INF finished listing all apps count=1
2023-02-17T11:09:22-06:00 INF warning: unable to process azure management groups; either the organization has no management groups or azurehound does not have the reader role on the root management group.
2023-02-17T11:09:22-06:00 INF finished listing all management group role assignments
2023-02-17T11:09:22-06:00 INF finished listing all management group descendants
2023-02-17T11:09:22-06:00 INF finished listing members for all groups
2023-02-17T11:09:22-06:00 ERR unable to continue processing role assignments for this role error="map[error:map[code:Request_ResourceNotFound innerError:map[client-request-id:a09b506e-758c-4bce-9c49-2f6df2e4776e date:2023-02-17T17:09:11 request-id:a09b506e-758c-4bce-9c49-2f6df2e4776e] message:Resource 'a0b1b346-4d3e-4e8b-98f8-753987be4970' does not exist or one of its queried reference-property objects are not present.]]" roleDefinitionId=a0b1b346-4d3e-4e8b-98f8-753987be4970
2023-02-17T11:09:22-06:00 INF finished listing all group owners
2023-02-17T11:09:22-06:00 INF finished listing all app owners
2023-02-17T11:09:23-06:00 INF finished listing all tenants count=2
2023-02-17T11:09:23-06:00 INF finished listing all service principals count=54
2023-02-17T11:09:23-06:00 INF finished listing all roles count=97
2023-02-17T11:09:23-06:00 INF finished listing all app role assignments
2023-02-17T11:09:23-06:00 INF finished listing all role assignments
2023-02-17T11:09:23-06:00 INF finished listing all service principal owners
2023-02-17T11:09:23-06:00 INF collection completed duration=2.192815s

shutting down gracefully, press ctrl+c again to force
```

Now we need to import the output file `all.json` into BloodHound:

![GIF showcasing the importing the all.json file in BloodHound via drap and drop method.](https://academy.hackthebox.com/storage/modules/69/azurehound_import2.gif)

We can start using BloodHound to identify different attack paths since there are no pre-built queries for Azure. We will use the `Transitive Object Control` option to determine what privileges we have from Isabella's account.

![GIF showcasing the Transitive Object control of the objects the user Isabella.Miller has.](https://academy.hackthebox.com/storage/modules/69/azurehound_isabella2.gif)

We can identify that Isabel has the `Password Administrator` role, which allows us to reset the passwords of non-administrator users.

One thing to consider when working with Azure is that, by default, users do not have the privilege to read all Azure objects. There may be objects in Azure that, if the user we authenticate with does not have rights to read, we will not be able to enumerate. For example, if we search and type `AZSubscription:` or `AZVM:`, BloodHound will not return any data because Isabella doesn't have the right to read the subscription object.