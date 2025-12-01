
## What is a process?

In Windows a process is **container** for a set of resources used when executing the instance of program.

At the highest level of abstraction a Windows process comprises the following:
- **Private virtual address space**: This a set of virtual memory that process can use.
- **An executable program**: This defines initial code and data is mapped into process's virtual address space.
- **A list of open handles**: These map to various system resource such semaphores, synchronization object and file that are accessible to all threads in the process.
- **A security context**: This is an **access token** that identifies the user, security groups, privileges, attributes, claims, capabilities, User Account Control (UAC) virtualization state, session, and limited user account state associated with the process, as well as the AppContainer identifier and its related sandboxing information.
- **A process ID**: This is a unique identifier, which is internally part of identifier called a ***client ID***.
- **At least one thread of execution**: Although an "empty" process is possible, it is (mostly) not useful.

## The state of process
A process can be in three state
- **Running**: This is the normal state indicates that process is in execution
- **Suspended**: This happens if **all the threads** in the process **are in suspended state**. This is unlikely to occur by the process itself but can be programmatically by calling the undocumented `NtSuspendProcess` native API on the process.  
- Not Responding: This can happen if a thread within the process that created a the user interface has not checked its message queue for UI-related activity for at least 5 seconds. The process (actually the thread that owns the window) may be busy doing some CPU-intensive work or waiting on something else entirely (such as an I/O operation to complete). Either way, the UI freezes up, and Windows indicates that by fading the window(s) in question and appending “(Not Responding)” to its title.

# Process kindship
**Each process also points to its parent** (which may be, but is not always, its creator process). If the parent no longer exists, this information is not updated. Therefore, **it is possible for a process to refer to a nonexistent parent**. This is not a problem, because nothing relies on this information being kept current.

example
- Open a cmd 
- type **title parent** 
- type **start cmd**
- In the second cmd type **tile child**
- In the child cmd type **mspaint**
- Close the child cmd
- Open a Task Manager and find Windows Command Processor app. You shold see the tile **parent**
- Right-Click and select **End Process Tree**

you can notice the first cmd (parent) disappear but the mspaint still in running.
