All of the AD enumeration data we collect is only useful if we know how to analyze it and use it to find misconfigurations and plan attack paths. Until now, we have used `SharpHound` ingestor to obtain all of this information, including user and computer properties, sessions, local admin rights, remote access privileges, etc. We can sort through this data and plan targeted attacks, but `BloodHound` provides a powerful tool to visualize links between all the data points we have collected so far. This can help plan an initial escalation/attack path or provide extra value to a client by finding more paths to obtain the "keys to the kingdom" or finding other misconfigurations or privilege issues that, once fixed, will further strengthen their AD environment.

---

## Mapping out INLANEFREIGHT.HTB

Once the data is imported into `BloodHound`, we can begin our review from the top down. Let's start with an overall domain analysis by typing `domain:INLANEFREIGHT.HTB` into the search bar.

![BloodHound interface showing node info for INLANEFREIGHT.HTB. Overview includes Users (34), Groups (60), Computers (7), OUs (6), GPOs (5). Node Properties display Object ID and Domain Functional Level (2016). Extra Properties include distinguished name and creation date.](https://academy.hackthebox.com/storage/modules/69/analyze_domain2.jpg)

From the results of the query, we can see the following information about the `INLANEFREIGHT.HTB` domain:

|**INLANEFREIGHT.HTB**||
|---|---|
|`Domain functional level`|2016|
|`Users`|34|
|`Groups`|60|
|`Computers`|7|
|`OUs`|6|
|`GPOs`|5|

This is a relatively small domain (and not 100% realistic with the few computers), but it gives us enough data to work with. The [domain functional level 2016](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/active-directory-functional-levels) makes us think that there may not be legacy servers in the domain (though they may still exist).

The next step is to look at the `Domain Users` group and see the rights the group has. This is important because every user in the domain will inherit any rights granted to this group, meaning that even a minor misconfiguration could have a major effect on the domain's security.

![Dashboard for DOMAIN USERS@INLANEFREIGHT.HTB: 2 sessions, 9 high-value targets, 31 direct and unrolled members, 0 foreign members, 3 first-degree memberships, 5 unrolled memberships.](https://academy.hackthebox.com/storage/modules/69/analysis_domain_users2.jpg)

Domain users have sessions on 2 hosts in the domain, have 31 direct members, and belong to 45 groups due to nested group membership. If we go to the `Local Admin Rights` section we see that it says we have 0, this is because the `Domain Users` group is not a member of the `Administrators` group on any of the machines. However, if we move to the `Outbound Object Control` section and click on `Transitive Object Control`" we will find all the objects that as `Domain Users` we have control over.

![Network diagram for DOMAIN USERS@INLANEFREIGHT.HTB showing connections to SRV01, ELIJESER, USERS, EVERYONE, AUTHENTICATED USERS, CERTIFICATE SERVICE DCOM ACCESS, and PRE-WINDOWS 2000 COMPATIBLE ACCESS with various relationships like MemberOf and GenericWrite.](https://academy.hackthebox.com/storage/modules/69/analysis_du_outbound.jpg)

Next, we can click on the `pathfinding` button and enter `DOMAIN USERS@INLANEFREIGHT.HTB` in the top field and `DOMAIN ADMINS@INLANEFREIGHT.HTB` in the bottom to see if we have any direct paths to Domain Admin for all users. The query returns no data, which means a path does not exist.

Next, we can start running some of the `Pre-Built Analytics Queries` to find additional interesting information.

It is a good idea to obtain a list of all `Domain Admins`. Here we see 3 direct members of the group and 4 unrolled members due to the `peter` user being a member of the nested group `ITSecurity`.

![Network diagram for DOMAIN-ADMINS@INLANEFREIGHT.HTB showing MemberOf connections to PETER, ITSECURITY, DAVID, JULIO, and ADMINISTRATOR.](https://academy.hackthebox.com/storage/modules/69/analysis_all_das2.jpg)

Next, look at the `Find Shortest Paths to Domain Admins` query. This returns a few paths. We can see some paths from users who are not members of the "Domain Admins" group. User `Gil` has `AddAllowedToAct` privileges on domain controller `DC01`, user `Pedro` has `GenericAll` permissions on container `Users`, `Sarah` can gain control of user `Pedro` and service account `svc_backups` has control over a GPO that is applied on domain controllers.

![Complex network diagram for DOMAIN ADMINS@INLANEFREIGHT.HTB showing connections with various users and groups like ADMINISTRATORS, ITSECURITY, DOMAIN CONTROLLERS, and policies with relationships such as MemberOf, Contains, GenericWrite, and AddKeyCredentialLink.](https://academy.hackthebox.com/storage/modules/69/analysis_path_to_da2.jpg)

Other interesting queries include:

|**Query**|**Result**|
|---|---|
|`Find Principals with DCSync Rights`|Find accounts that can perform the [DCSync](https://adsecurity.org/?p=1729) attack, which will be covered in a later module.|
|`Users with Foreign Domain Group Membership`|Find users that belong to groups in other domains. This can help mount cross-trust attacks.|
|`Groups with Foreign Domain Group Membership`|Find groups that are part of groups in other domains. This can help mount cross-trust attacks.|
|`Map Domain Trusts`|Find all trust relationships with the current domain.|
|`Shortest Paths to Unconstrained Delegation Systems`|Find the shortest path to hosts with [Unconstrained Delegation](https://adsecurity.org/?p=1667).|
|`Shortest Paths from Kerberoastable Users`|Show the shortest path to Domain Admins by selecting from all users in a dropdown that can be subjected to a [Kerberoasting](https://attack.mitre.org/techniques/T1558/003/) attack.|
|`Shortest Path from Owned Principals`|If we right-click a node and select `Mark user as owned` or `Mark computer as owned`, we can then run this query to see how far we can go from any users/computers that we have marked as "owned". This can be very useful for mounting further attacks.|
|`Shortest Paths to Domain Admins from Owned Principals`|Find the shortest path to Domain Admin access from any user or computer marked as "owned".|
|`Shortest Paths to High-Value Targets`|This will give us the shortest path to any objects that `BloodHound` already considers a high-value target. It can also be used to find paths to any objects that we right-click on and select Mark X as High Value.|

---

## Finding Sessions

BloodHound indicates the sessions we collect in the `Database Info` tab. We can also see the active sessions in nodes such as users, groups, or computers.

![Dashboard for DOMAIN ADMINS@INLANEFREIGHT.HTB: 1 session, 8 high-value targets, designated domain administrators, admin count true, with object ID and distinguished name details.](https://academy.hackthebox.com/storage/modules/69/analysis_sessions2.jpg)

In the image above, we can see that we have captured a session from the `Domain Admins` group. Clicking on the session number will show us the computer to which the user member of the `Domain Admins` group was connected during the enumeration:

![Dashboard for DOMAIN ADMINS@INLANEFREIGHT.HTB: 1 session, 8 high-value targets, admin details, connection from JULIO to DC01 with HasSession and MemberOf links.](https://academy.hackthebox.com/storage/modules/69/analysis_sessions_da2.jpg)

Similarly, we can find sessions for other users searching in groups or on computers. In the cypher query section, we will learn tricks to help us search for specific relationships in BloodHound.

---

## Owned Principals

BloodHound's `Mark as Owned` feature allows a user to mark a node as owned or controlled, indicating that the node is under their control. This feature is particularly useful for Red Team assessments as it allows them to mark nodes they have compromised or have control over, and quickly identify other nodes in the environment they may be able to target.

To use `Mark as Owned`, a user can simply right-click on a node in the BloodHound interface and select `Mark as Owned`. The node will then be marked with a skull icon, indicating that it is owned.

![Dashboard for HTB-STUDENT@INLANEFREIGHT.HTB: 1 session, 30 sibling objects, 0 high-value targets, 2 inbound GPOs, with display name, object ID, and last password change details.](https://academy.hackthebox.com/storage/modules/69/analysis_mark_as_owned.jpg)

Now we can go to the Analysis tab and select `Shortest Path from Owned Principals` and we can see what activities to perform with the users, group or teams that we have compromised.

![Analysis dashboard for HTB-STUDENT@INLANEFREIGHT.HTB: Kerberos interaction options, shortest paths analysis, connections to SRV01 and WS01 with AdminTo and CanPSRemote links.](https://academy.hackthebox.com/storage/modules/69/analysis_sp_from_owned.jpg)