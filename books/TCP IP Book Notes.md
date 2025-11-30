# What is a Network?
A network is a **set of  hardware devices connect together** either physically or logically. This allow them to exchange information or communicate.

# Path used to carry data on the network

## Circuit Switching
In the **circuit-switching** networking method a connection called **circuit** when is used for **whole** communication, is set up between two devices. 

In circuit-switching before communication can occur a circuit (a path from A to B) is established and never change until the communication ended.
![](../Assest/Pasted%20image%2020250716210811.png)

This type of network connection is used in **telephone system**.

## Packet Switching 
In the **packet-switching** network type instance no **specific path is used to transfer**.
In this case the data will be **chopped** up into small pieces called **packets** and sent over the network and they will be take **any number of paths** as the journey from one device to another. Nothing **circuit** will be set here.

![[Pasted image 20250706084526.png]]


# Connection-Oriented and Connectionless

A **conncetion-orented** protocol is one in which a **logical connection is first established**. ( For example a **TCP** protocol).
A **Connectionless** protocol the **data is just sent without a connection begin created**. ( For examaple a **UDP** protocol).

# Messages: Packets, Frames, Datagrams, and Cells

The communication between devices on packet-switched networks is based on items most generically called **messages**.
The pieces of information also go by other names such as:
- **Packets**: This term is used to refer a message sent by protocol operating at the **network layer** of the OSI Model
- **Datagram**: Is a **synonymous with packet** and is also used in a **network layer** of OSI Mode. It's also **often used** to refer to a message that is sent at a **higher level** of OSI Model
- **Frames**: This therm is used to refer to a message that travel at **low levels** of the OSI model. In particular in the **data link layer** messages
- **Cells**: It's the **same of frames** but in this case the messages **have a  fixed size**. for example the fixed-lenght, 53-nbyte messages sent in ATM are called **cells**.
- **Protocol Data Unit (PDU) and Service Data Unit (SDU):** These are the formal terms used in the OSI Model to describe protocol messages.

> [!TIP]
>  Communication between devices on packet-switched networks is based on items most generically called **messages**. These pieces of information also go by other names such as Packets,Datagram,Frame,Cell,PDU and SDU  which often correspond to protocols at particular layers of the OSI Model. The formal OSI terms for messages are PDU and SDU.

## Message Formatting: Headers, Payloads, and Footers 
Messages are the structures used to send information over networks. They vary greatly from one protocol or technology to the next in how they are used, and as just described, they are also called by many different names.


While the format of a particular message type depends entirely on the nature of the technology that uses it, messages on the whole tend to follow a fairly uniform overall structure. In generic terms, each message contains the following three elements

- **Header** :Information that is placed before the actual data. The header normally contains a small number of control-information bytes, which are used to communicate important facts about the data that the message contains and how it is to be interpreted and used. It serves as the communication and control link between protocol elements on different devices. 
- **Data**: The actual data to be transmitted, often called the payload of the message (metaphorically borrowing a term from the space industry!). Most messages contain some data of one form or another, but some messages actually contain none. They are used for only control and communication purposes. For example, these may be used to set up or terminate a logical connection before data is sent. 
- **Footer**: Information that is placed after the data. There is no real difference between the header and the footer, as both generally contain control fields. The term trailer is also sometimes used.

![](../Assest/Pasted%20image%2020250718084802.png)


> [!TIP]
> The general format of a networking message consists of a header, followed by the data or payload of the message, followed optionally by a footer. Header and footer information is functionally the same except for its position in the message; footer fields are only sometimes used, especially in cases where the data in the field is calculated based on the values of the data being transmitted


