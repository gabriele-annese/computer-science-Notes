As mentioned earlier, `BloodHound` uses the graph database [Neo4j](https://en.wikipedia.org/wiki/Neo4j) with [Cypher Query Language](https://neo4j.com/developer/cypher/) to analyze relationships, not a relational database like MSSQL and other databases. Cypher is based on SQL but was designed and optimized for [graph theory](https://en.wikipedia.org/wiki/Graph_theory). In graph theory, data is structured as nodes and relationships to show how objects are connected and related. `BloodHound` uses Cypher to identify relationships among the hundreds or thousands of objects that may be present in a domain environment. Cypher was initially developed with the graph database `Neo4j`, which BloodHound uses to store data collected via the `SharpHound` ingestor, but was made open source in 2015 through [openCypher](https://www.opencypher.org/).

`BloodHound` comes with many powerful pre-built queries and supports custom queries. By understanding Cypher, we can manipulate and examine BloodHound data in greater detail to better understand AD environments. This will enable us to identify relationships that attackers could exploit, which may have otherwise gone unnoticed for months or years. Armed with all built-in tools, tools such as `PowerView` and `BloodHound` with the ability to extend them to bend them to meet our needs, allowing for the extraction of data and identifying misconfigurations that others miss, will set us apart from other security professionals.

Instead of relying solely on the tool to detect obvious issues, we can leverage it to identify more nuanced and complex scenarios. By doing so, we can offer our clients added value and establish a trusted advisor relationship with them.

Before diving into some ways to extend `BloodHound with custom Cypher queries`, let's look at Cypher syntax to understand the language better.

---

## Cypher Syntax

The syntax of the Cypher query language is based on ASCII art, making it highly visual and easy to read. Cypher shows patterns of notes and relationships. It also includes filters based on labels and properties. To better understand how it works, let's start the neo4j database and connect to the database using the browser. Navigate to [http://localhost:7474/browser/](http://localhost:7474/browser/).

We need to ensure that we import BloodHound data through the BloodHound application. We can download a BloodHound.zip from resources and upload it to BloodHound.

Once we upload the database and connect to the Neo4j web console, we can execute the following query:

#### Cypher query to return all users

  Cypher Queries

```shell-session
MATCH (u:User) RETURN u
```

![GIF showcasing the execution of a query in neo4j.](https://academy.hackthebox.com/storage/modules/69/bh_neo4j_login_query2.gif)

This query uses the `MATCH` keyword to find all nodes labeled as `User` in the graph. We then use the `RETURN` keyword to return all the nodes found. Let's examine another query:

#### Cypher query to return the user peter

```shell-session
MATCH (u:User {name:"PETER@INLANEFREIGHT.HTB"}) RETURN u
```

The above query uses the `MATCH` keyword to find the user with the property `name` equal to `PETER@INLANEFREIGHT.HTB` and returns the user.

We can do the same query in a different way.

#### Cypher query to return the user peter

```shell-session
MATCH (u:User) WHERE u.name = "PETER@INLANEFREIGHT.HTB" RETURN u
```

Let's see one last example and include relationships. We will query which group the user `peter` is `MemberOf` and save it to a variable named `peterGroups`.

#### Cypher query to return peter's group membership.


```shell-session
MATCH (u:User {name:"PETER@INLANEFREIGHT.HTB"})-[r:MemberOf]->(peterGroups) 
RETURN peterGroups
```

![Neo4j browser showing query results for PETER@INLANEFREIGHT.HTB with MemberOf relationships to ITSECURITY and DOMAIN USERS. Node properties include admin count true, distinguished name, and domain details.](https://academy.hackthebox.com/storage/modules/69/bh_neo4j_query_groups.jpg)

---

## Cypher Attributes - Definitions

Let's see a graphical representation of a query and its components:

![Diagram illustrating a Cypher query: MATCH (n:User {name:'PETER@INLANEFREIGHT.HTB'})-[r:MemberOf]->(g:Group) RETURN g. Highlights nodes, relationships, labels, properties, and variables.](https://academy.hackthebox.com/storage/modules/69/cypher_diagram.png)

|Attribute|Definition|
|---|---|
|`Nodes`|Represented with parentheses around the corresponding attributes and information.|
|`Variable`|A placeholder represents a node or a relationship in a query. For example, in the query `MATCH (n:User) RETURN n`, the variable `n` represents the node labeled `User`.|
|`Relationships`|Depicted by dashes and arrows, with the relationship type in brackets. These show the direction of the relationship. Ex: `->` shows a relationship going one way, while `-` depicts a relationship going in both directions. In `BloodHound`, relationships are usually shown toward other privileges.|
|`Label`|Used to group nodes based on their properties or characteristics. Labels are denoted by a colon `:` and are added to a variable. For example, in the query `MATCH (n:User) RETURN n`, the label `User` is used to group nodes with a user's characteristics.|
|`Property`|Used to store additional information about a node or a relationship and is denoted by a curly brace `{}`. For example, in the query `MATCH (n:User {name:"PETER@INLANEFREIGHT.HTB", enabled:TRUE}) RETURN n`, the properties `name` and `enabled` are associated with the node `n` to store additional information about the user.|

---

## Playing with the Graph

We can also display the relationship between the User and the Group by returning all variables `n,r,g`:

#### Cypher query to return the user peter MemberOf relationship

```shell-session
MATCH (n:User {name:"PETER@INLANEFREIGHT.HTB"})-[r:MemberOf]->(g:Group) 
RETURN n,r,g
```

![GIF showcasing an execution of query to obtain the groups of the user Peter is part of in neo4j.](https://academy.hackthebox.com/storage/modules/69/bh_cypher_relation2.gif)

To do this graph in the BloodHound application, we can use the `Raw Query` bar, but We will need to add another variable, `p`, and wrap the query inside it, as follow:

#### Cypher query to return the user peter MemberOf relationship

```shell-session
MATCH p=((n:User {name:"PETER@INLANEFREIGHT.HTB"})-[r:MemberOf]->(g:Group)) 
RETURN p
```

![GIF showcasing an execution of query to obtain the groups of the user Peter is part of in BloodHound.](https://academy.hackthebox.com/storage/modules/69/bh_cypher_query_bhAPP2.gif)

---

## Cypher Keywords

Like SQL, Cypher uses keywords for specifying patterns, filtering, and returning results. The most common keywords are `MATCH`, `WHERE`, and `RETURN`.

|**Keyword**|**Description**|
|---|---|
|`MATCH`|Used before describing the search pattern for finding one or more nodes or relationships.|
|`WHERE`|Used to add more constraints to specific patterns or filter out unwanted patterns.|
|`RETURN`|Used to specify the results format and organizes the resulting data. We can return results with specific properties, lists, ordering, etc.|

Consider the following example query:

#### Return Peter's MemberOf relationships

```shell-session
MATCH p=((u:User {name:"PETER@INLANEFREIGHT.HTB"})-[r:MemberOf*1..]->(g:Group)) 
RETURN p
```

![Graph showing PETER@INLANEFREIGHT.HTB with MemberOf connections to groups like DOMAIN USERS, ITSECURITY, DOMAIN ADMINS, and others. Includes a raw query at the bottom.](https://academy.hackthebox.com/storage/modules/69/bh_cypher_query_path.jpg)

Here we assign the variables `u` and `g` to User and Group, respectively, and tell `BloodHound` to find matching nodes using the `MemberOf` relationship (or edge). We are using something new, `1..*`, in this query. In this case, it indicates that the path can have a minimum depth of 1 and a maximum depth of any number. The `*` means that there is no upper limit on the depth of the path. This allows the query to match paths of any depth that start at a node with the label `User` and traverse through relationships of type `MemberOf` to reach a node with the label `Group`.

We can also use a specific number instead of `*` to specify the maximum depth of the path. For example, `MATCH p=(n:User)-[r1:MemberOf*1..2]->(g:Group)` will match paths with a minimum depth of `1` and a maximum depth of `2`, meaning that the user must traverse through precisely one or two "MemberOf" relationships to reach the group node.

Back to the query, the result is assigned to the variable `p` and will return the result of each path that matches the pattern we specified.

Let's play a little bit with this query, and instead of showing both paths, let's match a path where the first group's name contains the substring `ITSECURITY`:

#### Find a path where the first group's name contains ITSECURITY

```shell-session
MATCH p=(n:User)-[r1:MemberOf*1..]->(g:Group)
WHERE nodes(p)[1].name CONTAINS 'ITSECURITY'
RETURN p
```

We have two nodes in the first group, `Domain Users` and `ITSECURITY`. The part `nodes(p)[1].name` refers to the name property of the first node in the path `p` obtained from the variable `nodes(p)`. We use the `CONTAINS` keyword only to return the path where the first group's name contains the substring `ITSECURITY`.

Instead of the `CONTAINS` keyword, we can also use the `=~` operator to check if a string matches a `regular expression`. To match a path where the first group's name contains the substring `ITSECURITY`, we can use the following query:

#### Find a path where the first group's name contains ITSECURITY

```shell-session
MATCH p=(n:User)-[r1:MemberOf*1..]->(g:Group)
WHERE nodes(p)[1].name =~ '(?i)itsecurity.*'
RETURN p
```

![Graph showing PETER@INLANEFREIGHT.HTB with MemberOf connections to ITSECURITY, DOMAIN ADMINS, ADMINISTRATORS, and DENIED RODC PASSWORD REPLICATION GROUP. Includes a raw query at the bottom.](https://academy.hackthebox.com/storage/modules/69/bh_cypher_query_path2.jpg)

We used two elements of a regular expression `(?i)` tells the regular expression engine to ignore the case of the characters in the pattern, and `.*` to match any number of characters.

**Note:** We can also use regular expressions in properties or any other element in a cypher query.

There are many other tricks we can use with the cypher query. We can find the cypher query cheat sheet [here](https://neo4j.com/docs/cypher-cheat-sheet/current/).

---

## Analyzing a Basic BloodHound Query

Let's look at a few built-in queries to `BloodHound`. We can enable the option `Query Debug Mode` in settings, which dumps queries into the `Raw Query` box, allowing us to see the query that `BloodHound` use behind the scene. The following query calculates the shortest paths to domain admins and is one we will use quite often to catch `low-hanging fruit`.

#### Shortest paths to domain admins

```shell-session
MATCH p=shortestPath((n)-[*1..]->(m:Group {name:"DOMAIN ADMINS@INLANEFREIGHT.HTB"})) 
WHERE NOT n=m 
RETURN p
```

![GIF showcasing the Query Debug Mode.](https://academy.hackthebox.com/storage/modules/69/bh_sp_to_da2.gif)

**Note:** The query return by BloodHound includes all relationship (edges) hardcoded which is faster, as it doesn't include Azure Edges. We use the `*..` expression, which means we are looking for any relationship. We did it to make it shorter for the example.

This query comes with a function `shortestPath` is a Cypher function that finds the shortest path between two nodes in a graph. It is used in the MATCH clause of a Cypher query to find the shortest path between a starting node `n` and an ending node `m` that match certain conditions.

We use the `WHERE NOT n=m` condition to exclude the possibility of the starting node and the ending node being the same node, as a node cannot have a path to itself.

---

## Advanced BloodHound Queries

Let's look at some more advanced queries that can be useful to us during an engagement. These are queries that help further unlock the power of the `BloodHound` tool to find data that can help inform attacks that can help us progress towards our assessment's goal.

The first query we will show is the most important one. With this query, we can find almost any path in the domain shared by PlainText. He has been using this script to compromise any Active Directory during engagements, labs, and certifications labs.

#### ShortestPath from node that contains peter to any node

```shell-session
MATCH p = shortestPath((n)-[*1..]->(c)) 
WHERE n.name =~ '(?i)peter.*' AND NOT c=n 
RETURN p
```

![BloodHound graph showing PETER@INLANEFREIGHT.HTB with connections to DOMAIN USERS, ITSECURITY, DOMAIN ADMINS, and INLANEFREIGHT.HTB. Dense network of nodes and relationships, with a raw query at the bottom.](https://academy.hackthebox.com/storage/modules/69/bh_cypher_query_magic.jpg)

This script search for the shortestPath from any node to any node. In this example, if we manage to compromise Peter, but he doesn't have a path to Domain Admin or a High-Value Target, most likely, we won't get any results using default queries in BloodHound. However, by utilizing this query, we can determine if peter has access to a machine, a user, a group, GPO, or anything in the domain.

The purpose of this script is to streamline the process of exploring our options after successfully compromising a user, computer, or group. If we compromise a user, we employ the query to determine the potential paths we can pursue with that user. Likewise, if we compromise a computer or group, we use the same script to identify the available opportunities for further exploitation.

**Note:** We can replace the function `shortestPath` with `allshortestpaths` to get every single relationship available.

If we compromise a user and this script doesn't give you any result, we can use PowerView or SharpView to display user privileges over another object in AD.

#### PowerView Identify ACL

```powershell-session
PS C:\htb> Import-Module c:\tools\PowerView.ps1
PS C:\htb> Get-DomainObjectAcl -Identity peter -domain INLANEFREIGHT.HTB -ResolveGUIDs
...SNIP...
```

**Note:** The latest version of BloodHound includes `Self` privileges, which were not included in previous versions. For more information about using this PowerView method, we can take a look at: [ACL Enumeration](https://academy.hackthebox.com/module/143/section/1485) section in [Active Directory Enumeration & Attacks](https://academy.hackthebox.com/module/details/143) module.

## Custom Queries examples

The following query finds specific rights that the Domain Users group should not have over a computer node:

#### Finds specific rights that the Domain Users group should not have

```shell-session
MATCH p=(g:Group)-[r:Owns|WriteDacl|GenericAll|WriteOwner|ExecuteDCOM|GenericWrite|AllowedToDelegate|ForceChangePassword]->(c:Computer) 
WHERE g.name STARTS WITH "DOMAIN USERS" 
RETURN p
```

**Note:** We can add as many relationships as we want.

Some custom queries can only be run against the database from the `Neo4j` console via the browser accessible at `http://localhost:7474/browser` with the same credentials when starting `BloodHound`. For example, we can run this query to find all users with a description field that is not blank. This is an edge case, but it is common for account passwords to be stored in this field.

#### Find all users with a description field that is not blank


```shell-session
MATCH (u:User) 
WHERE u.description IS NOT NULL 
RETURN u.name,u.description
```

![Neo4j browser showing query results for users with descriptions: ADMINISTRATOR, KRBTGT, and GUEST at INLANEFREIGHT.HTB, with respective descriptions for each account.](https://academy.hackthebox.com/storage/modules/69/bh_cypher_query_descripcion.jpg)

We can use the following query to find all local administrators and the host they are admin. This query can help present to a client the extent of local admin privileges in their network.

#### Find all local administrators and the host they are admin


```shell-session
MATCH (c:Computer) OPTIONAL MATCH (u1:User)-[:AdminTo]->(c) OPTIONAL MATCH (u2:User)-[:MemberOf*1..]->(:Group)-[:AdminTo]->(c) WITH COLLECT(u1) + COLLECT(u2) AS TempVar,c UNWIND TempVar AS Admins 
RETURN c.name AS COMPUTER, COUNT(DISTINCT(Admins)) AS ADMIN_COUNT,COLLECT(DISTINCT(Admins.name)) AS USERS 
ORDER BY ADMIN_COUNT DESC
```

![Neo4j browser showing query results for computers with admin counts: WS01 with 5 admins, DC01 with 4, and SRV01 with 4. Lists associated users for each computer.](https://academy.hackthebox.com/storage/modules/69/bh_cypher_query_computeradmins.jpg)

Finally if we are looking for an edge, we can use cypher query too. For example, if we want to get any node that has `WriteSPN` we can use the following cypher query:

#### Find WriteSPN edge

```shell-session
MATCH p=((n)-[r:WriteSPN]->(m)) RETURN p
```

![Graph showing a WriteSPN relationship from INDHI@INLANEFREIGHT.HTB to NICOLE@INLANEFREIGHT.HTB. Includes a raw query at the bottom.](https://academy.hackthebox.com/storage/modules/69/cypher_find_edge.jpg)

**Note:** We can replace `WriteSPN` with any edge we are insterested.

There are many cheat sheets out there with useful `BloodHound` queries.

- [https://gist.github.com/jeffmcjunkin/7b4a67bb7dd0cfbfbd83768f3aa6eb12](https://gist.github.com/jeffmcjunkin/7b4a67bb7dd0cfbfbd83768f3aa6eb12)
- [https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/](https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/)

Try out making some of your own!

---

## Saving Custom Queries

On Windows, the `AppData\Roaming\bloodhound` directory holds a variety of configuration files used by BloodHound.

![File explorer showing the Bloodhound folder in AppData/Roaming. Contains folders like blob_storage, Cache, and files like config.json, customqueries.json, and images.json.](https://academy.hackthebox.com/storage/modules/69/bloodhound_dir1.png)

On Linux, these are stored in `/home/<username>/.config/bloodhound` or `/root/.config/bloodhound` if running as root.

#### BloodHound config directory


```shell-session
BusySec@htb[/htb]$ ls /root/.config/bloodhound

 blob_storage   Cookies              Dictionaries  'Local Storage'
 Cache          Cookies-journal      GPUCache      'Network Persistent State'
'Code Cache'   'Crash Reports'       images         Preferences
 config.json    customqueries.json   images.json
```

The `config.json` file holds the current `BloodHound` configuration, including performance options, included edges, etc.

#### BloodHound config.json file

```shell-session
{
    "performance": {
        "edge": 4,
        "lowGraphics": false,
        "nodeLabels": 1,
        "edgeLabels": 1,
        "darkMode": true,
        "debug": true
    },
    "edgeincluded": {
        "MemberOf": true,
        "HasSession": true,
        "AdminTo": true,
        "AllExtendedRights": true,
        "AddMember": true,
        "ForceChangePassword": true,
        "GenericAll": true,
        "GenericWrite": true,
        "Owns": true,
        "WriteDacl": true,
        "WriteOwner": true,
        "CanRDP": true,
        "ExecuteDCOM": true,
        "AllowedToDelegate": true,
        "ReadLAPSPassword": true,
        "Contains": true,
        "GpLink": true,
        "AddAllowedToAct": true,
        ...SNIP...
    }
}
```

The other file that we will focus on is the `customqueries.json` file. By default, it is blank.

#### Default customqueries.json


```shell-session
{"queries": []}
```

We can add to this file as we build and test queries. Clicking on the pencil icon next to `Custom Queries` in the `Queries` tab will open this file. As we add custom queries, the list will populate.

Let's create a custom cypher query to identify `allshortestpaths` from peter to any node.

#### Identify allshortestpaths from peter to any node


```shell-session
MATCH p = allshortestPaths((n)-[*1..]->(c)) 
WHERE n.name =~ '(?i)peter.*' AND NOT c=n 
RETURN p
```

![GIF showcasing the Create Custom Query feature.](https://academy.hackthebox.com/storage/modules/69/bh_cypher_to_anything2.gif)

This action adds the following content to the `customqueries.json` file:

#### customqueries.json file with previous query

```shell-session
{
    "queries": [
        {
            "name": "From Peter to Anything",
            "category": "Shortest Paths",
            "queryList": [
                {
                    "final": true,
                    "query": "MATCH p = allshortestPaths((n)-[*1..]->(c))  WHERE n.name =~ '(?i)peter.*' AND NOT c=n  RETURN p",
                    "allowCollapse": true
                }
            ]
        }
    ]
}
```

We can make this Custom Query even more interesting. BloodHound has functionality that allows us to mark a node as `Owned`, we can mark any user, computer, etc,. in the BloodHound GUI as `Owned` by right-clicking it and clicking `Mark User as Owned`. This means that we somehow get control of this object.

We can customize this script to ask us to select a user marked as owned and perform the search to avoid hardcoding the name.

BloodHound queries in the Analysis tab are loaded from the `PrebuiltQueries.json` file. We can find it in the BloodHound directory or [Github](https://github.com/BloodHoundAD/BloodHound/blob/master/src/components/SearchContainer/Tabs/PrebuiltQueries.json).

To accomplish our goal, we will use a variation of the `Find Shortest Paths to Domain Admins`. We need to replace the content of `customqueries.json` with the following text:

#### customqueries.json - Search From Owned to Anything

```shell-session
{
    "queries": [
        {
            "name": "Search From Owned to Anything",
            "category": "Shortest Paths",
            "queryList": [
                {
                    "final": false,
                    "title": "Select the node to search...",
                    "query": "MATCH (n {owned:true}) RETURN n.name",
                    "props": {
                        "name": ".*"
                    }
                },
                {
                    "final": true,
                    "query": "MATCH p = allshortestPaths((n)-[*1..]->(c))  WHERE n.name = $result AND NOT c=n  RETURN p",
                    "allowCollapse": true,
                    "endNode": "{}"
                }
            ]
        }
    ]
}
```

This script has two queries. The first search for all nodes marked as owned and provides a list where we can select any node. The second use the selection and saves it into a variable named `$result` and then run the second query.

![GIF showcasing the execution of a saved Custom Query within the Analysis tab.](https://academy.hackthebox.com/storage/modules/69/bh_cypher_custom_query2.gif)

**Note:** If BloodHound is open when we update the `customqueries.json` file, we need to click the update icon to refresh its content.