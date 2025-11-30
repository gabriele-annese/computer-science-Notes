Remote services are essential tools for businesses and IT departments, enabling remote access and management of systems, facilitating collaboration, and improving efficiency. These services allow administrators to manage and troubleshoot systems without needing physical access, which is especially valuable in distributed and large-scale environments.

## Purpose of Remote Services

Remote services provide several benefits, including:

- `Remote management`: Allowing IT staff to configure, update, and troubleshoot systems from anywhere.
- `Resource sharing`: Enabling users to access shared files, printers, and applications across the network.
- `Collaboration`: Facilitating communication and collaboration between remote teams.
- `Efficiency`: Reducing the need for physical presence, saving time and travel costs.

As attackers, we can abuse these services to move laterally within a network, escalate privileges, and maintain persistence.

## Types of Remote Services

Based on the [T1021 - MITRE ATT&CK framework technique](https://attack.mitre.org/techniques/T1021/), there are several types of remote services that we can exploit for lateral movement. In this section, we will focus on the following:

- `Remote Desktop Protocol (RDP)`: RDP is a proprietary protocol developed by Microsoft, providing a user with a graphical interface to connect to another computer over a network connection. It is widely used for remote administration and technical support.
- `SMB / Windows Shares`: Server Message Block (SMB) is a network file sharing protocol that allows applications and users to read and write to files and request services from server programs in a network. Windows Shares use SMB to enable file and printer sharing between machines.
- `Windows Management Instrumentation (WMI)`: WMI is a set of specifications from Microsoft for consolidating the management of devices and applications in a network from Windows computing systems. It provides powerful capabilities for remote management and data collection.
- `Windows Remote Management (WinRM)`: WinRM is the Microsoft implementation of the WS-Management protocol, which provides a secure way to communicate with local and remote computers using web services. It is commonly used for remote management tasks.
- `Distributed Component Object Model (DCOM)`: DCOM is a Microsoft technology that allows software components to communicate directly over a network. It extends the Component Object Model (COM) to support communication among objects on different computers.
- `Secure Shell (SSH)`: SSH is a cryptographic network protocol for operating network services securely over an unsecured network. It is widely used for remote command-line login and remote command execution.

## Enumeration Methods

To exploit these remote services, we first need to identify them within the network. Enumeration involves discovering available services and gathering information about them. Common enumeration methods include:

- `Port scanning`: Identifying open ports and services running on them.
- `Service banners`: Capturing and analyzing service banners to gather version and configuration information.
- `Active Directory`: Querying Active Directory to retrieve information about systems and their services.

Using the credentials we have obtained, we can authenticate to these services and attempt lateral movement. Different types of credentials we might use include:

- `Passwords`: Traditional form of authentication where a user provides a secret word or phrase to verify their identity.
- `NTLM Hashes`: Cryptographic representations of passwords used in Windows environments for authentication. We can use these hashes to authenticate without needing the actual password, with technique named Pass the Hash.
- `NTLMv2 Hashes`: An improved version of NTLM hashes that provides better security. These hashes are also used for authentication in Windows environments. We can use NTLM Relay attacks to abuse those hashes in the network for lateral movement.
- `AES256 Keys`: Advanced Encryption Standard (AES) with 256-bit keys used for encrypting data. In some contexts, these keys can be used for authentication on Windows system using Rubeus or Mimikatz.
- `Tickets (Kerberos)`: Kerberos is an authentication protocol that uses tickets to allow nodes to prove their identity securely. We can forge or capture tickets and use then to authenticate and move laterally within a network.