In the previous section, we discussed cypher queries and how we can use them to discover paths leading us to our goal. We included some valuable queries for the BlueTeam to provide a general idea of how BlueTeamers can use BloodHound to identify weaknesses and create a plan of action to remedy them.

In this section, we will discuss how BloodHound information can help us better protect our Active Directory infrastructure and share some tools that will make it easier to use BloodHound defensively.

## BloodHound to improve security

Blue teams play a critical role in ensuring the security of an organization. They are responsible for monitoring, identifying, responding to cyber threats, and implementing proactive measures to prevent future breaches. Over the past few years, we have observed how the BlueTeam team can proactively use offensive security tools like BloodHound to protect their infrastructure.

BloodHound can be used in various ways to help improve an organization's security. For example, it can be used to understand complex relationships between users, groups, and permission. BlueTeams can also identify misconfigurations and possible attack vectors within the Active Directory environment with cipher queries. By regularly monitoring changes in the active directory, BlueTeams can proactively identify potential risks. This proactive approach helps defense teams to stay ahead of the game and create a plan to remediate any security weaknesses before attackers can exploit them.

This section will use two open-source projects that use BloodHound data for BlueTeams. The first one will be `BlueHound`, which will help automatically collect, analyze, and report data from the BloodHound database. The 2nd is `PlumHound`, which we will mainly use to identify how to break paths from one node to another.

## BlueHound

[BlueHound](https://github.com/zeronetworks/BlueHound) is an open-source tool that helps blue teams identify critical security issues by combining information about user permissions, network access, and unpatched vulnerabilities. BlueHound reveals the paths attackers would take if they were inside network.

BlueHound main features include:

- **Full Automation**: We can perform the entire cycle of collection, analysis, and reporting with just a click of a button.
- **Community Driven**: The tool facilitates sharing, making it easy to share knowledge, best practices, collection methodologies, and more by exporting and importing BlueHound configuration.
- **Easy Reporting**: We can create a customized report intuitively without the need to write any code.
- **Easy Customization**: Users can add any custom collection method to BlueHound, and even include their custom parameters or icons for their graphs.

![BlueHound dashboard showing logical paths: Paths from vulnerable hosts, Domain Admins with sessions to non-DCs, Shortest paths to Domain Admins, Paths from Kerberoastable users, Paths to Crown Jewels, and Ransomulator graph.](https://academy.hackthebox.com/storage/modules/69/bluehound.png)

**Note:** Although we can combine multiple tools in BlueHound, in this section, we will use only the functionality to automate SharpHound's data collection, analysis, and reporting.

## Installing BlueHound

We can download BlueHound's compiled version for Windows from the [github releases link](https://github.com/zeronetworks/BlueHound/releases), but we can also use it on Linux or MacOS.

**Note:** At the time of writting, BlueHound is version 1.1.0.

Next, we need to unzip `BlueHound-win32-x64-1.1.0.zip`.

#### Unzip BlueHound

  BloodHound for BlueTeams

```powershell-session
PS C:\Tools> Expand-Archive .\BlueHound-win32-x64-1.1.0.zip .
```

**Note:** It may take a while to unzip, as BlueHound zip is around 170MB.

After extracting it, we need to open the file `BlueHound.exe`, click Login and use the BloodHound credentials we use to set up the database. In our example, credentials are user `neo4j` password `Password123`.

![GIF showcasing the start of BlueHound.](https://academy.hackthebox.com/storage/modules/69/bluehound_opening2.gif)

## Using BlueHound

The `Data Import` option in BlueHound allows us to automatically import data from sources such as SharpHound, ShotHound, Vulnerability Scanners, etc. We will disable all options but SharpHound.

![BlueHound data import tools menu showing options: SharpHound, ShotHound, Vulnerability Scanners Results Upload, Cartography - AWS, and Cartography - GCP. Includes options for serial or parallel execution, scheduling, and running all tools.](https://academy.hackthebox.com/storage/modules/69/bluehound_import_1.jpg)

Next, we need to download SharpHound, click edit settings, and set the `Tool path` and the `Arguments`. We can find SharpHound at `C:\Tools\SharpHound.exe`. To see the arguments, we need to type the SharpHound's options and press Enter.

![GIF showcasing the import of SharpHound and the setup of the parameters to be executed.](https://academy.hackthebox.com/storage/modules/69/bluehound_importing_sharphound2.gif)

We can also automate SharpHound collection using the `schedule` option and select its frequency (daily, weekly, or monthly):

![BlueHound scheduling options for data import tools: Frequency set to weekly, day set to Monday, start time at 12:00 AM. Options to cancel or save.](https://academy.hackthebox.com/storage/modules/69/bluehound_import_2.jpg)

Once we have data loaded, we can use the `Configurations` tab to set up the basic information used by the queries (e.g., Domain Admins group, crown jewels servers). Let's use the following configuration:

![BlueHound configurations for Domain Controllers, Domain Admins Group, and Crown Jewels. Set to DOMAIN CONTROLLERS@INLANE..., DOMAIN ADMINS@INLANE..., and SRV01.INLANEFREIGHT.HTB respectively.](https://academy.hackthebox.com/storage/modules/69/bluehound_configurations.jpg)

Next, we can use the `Query Runner` option in the menu and click `RUN ALL` to prepare the reports.

![BlueHound Query Runner menu with options for Logical Paths and Network-Enabled Paths. Includes queries like Paths from vulnerable hosts, Domain Admins with sessions to non-DCs, and Paths to Crown Jewels. Max parallel queries set to 5.](https://academy.hackthebox.com/storage/modules/69/bluehound_runallqueries.jpg)

All tabs should now have some data. Default reports for BlueHound include data from other sources such as ShotHound and Vulnerability Scanners. Since we are not using those tools, some reports will remain unfilled.

![BlueHound dashboard showing Logical Paths: Paths from vulnerable hosts (no data), Domain Admins with sessions to non-DCs, Shortest paths to Domain Admins, Paths from Kerberoastable users, Paths to Crown Jewels, and Ransomulator graph.](https://academy.hackthebox.com/storage/modules/69/bluehound_dashboard.jpg)

Now our job as BlueTeamers is to understand the data that makes sense to monitor in our environment, and this could be:

- Administrators with sessions on non-Domain machines.
- Dangerous privileges in the Domain Users group
- Paths from Kerberoastable users
- Users with higher privileges on computers
- Users that do not require pre-authentication
- Users with more sessions

The list can be much longer and will depend on each environment. The advantage that BlueHound offers is that it allows us to create our Cypher queries to monitor what is most important to us.

## BlueHound Customization

BlueHound allows us to modify existing queries, add new queries, create new tabs, and visualize the data according to our needs.

To create a new query, we can click on the box with the `+` sign, define a report name, click on the three vertical dots, define the type and size, and include our query. In the following example, we will create a table that consists of the number of enabled users of the active directory with the following query:

```
MATCH (u:User {enabled:true}) 
RETURN COUNT(u)
```

![GIF showcasing the execution of a custom query.](https://academy.hackthebox.com/storage/modules/69/bluehound_custom_char2.gif)

We can add/delete any char or tab and create our dashboards. We can also import and export dashboards.

Let's import the custom dashboard `C:\Tools\bluehound_dashboard_htb.json` with the following steps:

- Go to `Import Config`.
- Select the file to import and import it.
- Go to the `Configurations` tab and complete the information (Domain Controllers, Domain Admins, and SRV for this example).
- Close BlueHound (some times BlueHound freeze while trying to run some queries. If it happens, we can close and re-open it).
- Open BlueHound and click on `Query Runner`.
- Click on `RUN ALL` to fill all reports with data.

![GIF showcasing the Runner functionality.](https://academy.hackthebox.com/storage/modules/69/bluehound_import_conf2.gif)

To get more information about BlueHound, check out their [introductory video](https://youtu.be/WVup5tnURoM), [blog post](https://zeronetworks.com/blog/bluehound-community-driven-resilience/) and [Nodes22 conference talk](https://www.youtube.com/watch?app=desktop&v=76MWt8uugAg).

## PlumHound

[PlumHound](https://github.com/PlumHound/PlumHound) operates by wrapping BloodHoundAD's powerhouse graphical Neo4J backend cypher queries into operations-consumable reports. Analyzing the output of PlumHound can steer security teams in identifying and hardening common Active Directory configuration vulnerabilities and oversights.

## Installing PlumHound

We need Python installed and download the released zip file, unzip it, and install the requirements with pip.

```cmd-session
C:\Tools\PlumHound> python -m pip install -r requirements.txt
...SNIP...
```

We can confirm if it works with the `--easy` option and the `-p` option to specify the password.

```cmd-session
C:\Tools\PlumHound>python PlumHound.py --easy -p Password123

        PlumHound 1.5.2
        For more information: https://github.com/plumhound
        --------------------------------------
        Server: bolt://localhost:7687
        User: neo4j
        Password: *****
        Encryption: False
        Timeout: 300
        --------------------------------------
        Task: Easy
        Query Title: Domain Users
        Query Format: STDOUT
        Query Cypher: MATCH (n:User) RETURN n.name, n.displayname
        --------------------------------------
INFO    Found 1 task(s)
INFO    --------------------------------------
on 1:
on 1: n.name                           n.displayname
      -------------------------------  ---------------
      ADMINISTRATOR@INLANEFREIGHT.HTB
      KRBTGT@INLANEFREIGHT.HTB
      JULIO@INLANEFREIGHT.HTB          julio
      HTB-STUDENT@INLANEFREIGHT.HTB    htb-student
      PETER@INLANEFREIGHT.HTB          peter
      DAVID@INLANEFREIGHT.HTB          david
      MARK@INLANEFREIGHT.HTB           mark
      RYAN@INLANEFREIGHT.HTB           ryan
      JARED@INLANEFREIGHT.HTB          jared
      GRACE@INLANEFREIGHT.HTB          grace
on 1:
Executing Tasks |██████████████████████████████████████████████████| Tasks 1 / 1  in 2.1s (0.84/s)

        Completed 1 of 1 tasks.
```

## Using PlumHound Path Analyzer

PlumHound has multiple uses and different things we can do with this tool. In this example, we will use the `Path Analyzer` option (`-ap`) to understand what relationship we have to remove to break the attack paths we detect.

The Analyze Path function requires a `label`, or a `start node` and an `end node`, and then iterates through all paths to identify which relationship(s) to remove to break the attack path. This is useful when you want to provide your AD Admins with concrete actions they can take to improve your overall AD Security Posture.

Let's take as an example the dangerous Domain Users permissions between `Domain Users` and `WS01`, and identify which privilege we need to remove to break the path:

```cmd-session
C:\Tools\PlumHound> python PlumHound.py -p Password123 -ap "DOMAIN USERS@INLANEFREIGHT.HTB" "WS01.INLANEFREIGHT.HTB"

        PlumHound 1.5.2
        For more information: https://github.com/plumhound
        --------------------------------------
        Server: bolt://localhost:7687
        User: neo4j
        Password: *****
        Encryption: False
        Timeout: 300
        --------------------------------------
        Task: Analyzer Path
        Start Node: DOMAIN USERS@INLANEFREIGHT.HTB
---------------------------------------------------------------------
Analyzing paths between DOMAIN USERS@INLANEFREIGHT.HTB and WS01.INLANEFREIGHT.HTB
---------------------------------------------------------------------
Removing the relationship GpLink between SCREENSAVER@INLANEFREIGHT.HTB and WORKSTATIONS@INLANEFREIGHT.HTB breaks the path!
Removing the relationship Contains between WORKSTATIONS@INLANEFREIGHT.HTB and WS01.INLANEFREIGHT.HTB breaks the path!
INFO    Tasks Generation Completed
Tasks: []
Executing Tasks |██████████████████████████████████████████████████| Tasks 0 / 0  in 0.1s (0.00/s)

        Completed 0 of 0 tasks.
```

**Note:** We encountered some unidentified relationships between nodes during PlumHound testing. For example, "Domain Users" with the user "Elieser" does not bring any results, but the relationships exist. We should also keep in mind that not all recommendations are safe. For example, to break the path between SVC_BACKUPS and Domain Admins, we could remove DC01 from the Domain Controller container, but this will affect the functionality of the domain controller in the environment.
