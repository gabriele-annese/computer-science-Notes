Offensive security professionals are charged with performing relevant and realistic testing in order to enable network defenders to identify and respond to real world threats.  Ransomware is arguably the most relevant cyber threat today, with alarming trends in 2023 highlighting the risk posed to organizations.  According to analysis from Sophos , a staggering two-thirds of 3000 IT/cybersecurity leaders in 14 different countries reported being impacted by ransomware in 2023, with the average ransom payment almost double the 2022 average:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/73cdb2f3e410749623de2b7eddcd4f07.png)

Being able to simulate ransomware, even partially, as an effect during a red team exercise is an attractive capability, so we will build a BOF to enable this.  There is a fine line to be walked during a project like this; real ransomware is destructive by design, and the last thing we want to do during an authorized red team operation is degrade the client's network in unintended or irreparable way.  Careful consideration will need to be given during the design process to develop a tool that provides some level of simulation of ransomware without the associated risk of severely degrading the system that it is deployed on.  This will be fleshed out more after we first review some threat intel and malware analysis of real ransomware samples.

This project will be developed in the Windows VS template, but you are of course free to follow along on Linux if you so choose.

## Background Research and Design Theory

We will refer to a [txOne](https://www.txone.com/blog/malware-analysis-lockbit-3-0/) article in which they analyze Lockbit 3.0, a prolific threat in the ransomware game.  This article provides a wealth of details on how the malware works, but we are primarily concerned with the changes it makes to the victim system:

- Stops the Volume Shadow Copy Service (VSS) and delete shadow copies from disk to inhibit recovery efforts.
    
- Disables Windows Defender.
    
- Stops the Windows Event Log Service and clears existing logs.
    
- Stops a number of services and processes that may be holding files open so that the files may be encrypted.
    
- Encrypts and renames files on the target machine.
    
- Writes out a ransom note in a .txt file on the desktop.
    
- Drops an image with instructions pointing to the ransomware note and sets it as the background image for the computer.
    
- Drops an .ico file and changes the icon of files to a custom ransomware one.
    

A number of these are non-starters for our purposes; for example, there is no justifiable reason to delete shadow copies or event logs for the sake of simulation.  When the destructive, risky, and/or unnecessary are removed, the list of remaining effects is:

- Rename files on the target machine.
    
- Write out a ransom note in a .txt file on the desktop.
    
- Drop an image with instructions pointing to the ransomware note and set it as the background image for the computer.
    

We could change the icons of files too, but you should remember that any change made is one that you are also responsible for reverting afterwards; little is gained by changing icons, so we will pass on this one.  We won't stop/delete services or actually encrypt files for obvious reasons, but we can provide visual cues and surface level changes that are common to real ransomware while keeping impact to the system to a minimum. 

We can limit the file manipulation to the current user's desktop only, and we won't recurse through any directories we find there either.  Files on the desktop can be renamed to prepend 'ENCRYPTED.' to the file name, which leaves files accessible and functional because the extension remains unmodified.  And of course, in the note that is dropped, we will make clear that this is a simulation and provide instructions on how to revert all changes should we lose access or our ability to revert the changes ourselves.

With a plan established, we can get started writing the BOF.

