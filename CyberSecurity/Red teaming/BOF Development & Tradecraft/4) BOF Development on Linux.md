We will begin by making a simple BOF to:
- Pop a message box and print a user-specified message.
- Echo a number given as an argument using the Beacon API.

Make a folder for the project within the BOF_Course directory on your Linux machine and then open it in Visual Studio Code (VSC) by navigating to **File->Open Folder** and selecting it.

The first file we need to create is _beacon.h_.  This is a header file provided by the Cobalt Strike team on GitHub [here](https://github.com/Cobalt-Strike/bof_template/blob/main/beacon.h) that contains a number of structures and Beacon API definitions that we require for use in our BOF.  Just about every BOF project on GitHub contains a copy of this file, though it may be a previous version with fewer Beacon APIs defined.  The Beacon API is steadily being updated and expanded with new functionality, so it's wise to look for and grab the latest version from the official repo.

Create a new file in your project folder using the **New File...** icon and name it _beacon.h_:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/24dd6c6772374e63301c9b3127f04722.png)

Copy and paste the contents of the code block below into the file (this is copied from the GitHub repo linked above):

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/5f60046048b320d5b833c094ae63e782.png)

Create another new file _main.c_.  This file will contain our actual BOF code and we will begin by including the windows.h header which contains definitions for many of the WinAPIs and related structures that we will use.  The _beacon.h_ file will additionally be included so that we have access to the Beacon APIs.  We will conclude the basic setup of _main.c_ by defining the go function:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/75fa41d088fec1b4d5429e7173529ceb.png)

Note that system header files are included using carrots, whereas user-defined header files are included with quotations.  The go function is the BOF equivalent of a normal program's main; however this is completely arbitrary, as we can manually specify the name of the function that should be called when the BOF runs.  For simplicity we will leave it as is.

A staple of BOFs is the use of the `datap` structure and the `BeaconDataParse` Beacon API.  This is how BOFs unpack arguments passed to them for use at runtime.  As mentioned in the COFFLoader section, each data type requires a specific Beacon API to unpack it.  One of our goals for this BOF is to display a user-specified string in a message box.  We could use either an ANSI (CHAR) or a Unicode (WCHAR) string for this purpose, but for simplicity we will use a normal ANSI string which corresponds to the z data type and the `BeaconDataExtract` Beacon API:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/6c678cc914813175898e68ed595f1eaf.png)

We will turn to Microsoft Learn for the API definition of [MessageBoxA](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxa):

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/fff5c30d5bf20d24ab4c280adffd880a.png)

After consulting the documentation, we assemble the MessageBoxA API call using the variable extracted from the packed BOF arguments:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/7a925f82670b5f9a42ed8b3425976cb0.png)

We also need to extract a number that is provided as the second argument to the BOF.  The `BeaconDataInt` Beacon API is used for this and we will call it after `BeaconDataExtract`:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/00c09e9293a89a7c246d737d9e6b2344.png)

The `BeaconPrintf` Beacon API can then be used to print the number variable using the appropriate [c format specifier](https://www.tutorialspoint.com/format-specifiers-in-c):

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/270d8aaf84f22d4fe3ed5ccac3f5d053.png)

BeaconPrintf is the most common way to return data from a BOF to the C2 server.  Functionally it works the exact same as printf in C, except it requires a callback format specifier as the first argument (`CALLBACK_OUTPUT`).  There are four of these callback types defined within beacon.h, but the two we will use most often are CALLBACK_OUTPUT and `CALLBACK_ERROR`.  Both result in a message being sent back to the C2 server, with the difference related to the format as seen in Cobalt Strike:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/b0483a2ca66aa4791ecbf83938233d21.png)

Altogether, our complete code looks like this:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/296e632365f95ce48f61bbd3be7e7e56.png)

We are now ready to compile our code into an object file.  We will do this using the Mingw cross-compiler and will only compile the x64 version for now:  `x86_64-w64-mingw32-gcc -o project1.x64.o -Os -c main.c`.

Mingw compiler flags are numerous and confusing, but luckily we don't need many for our purposes.  The breakdown of this command can be seen in the following table:

|   |   |
|---|---|
|**Compiler flag**|**Meaning**|
|-o project1.x64.o|Place output in the project1.x64.o file|
|-Os|Optimize the compiled code for size. This results in a smaller binary.|
|-c main.c|Compile main.c, but do not link it. This results in an object file being generated instead of a full executable.|

We can now transfer the compiled _project1.x64.o_ to the Windows test machine and use COFFLoader to run it.  We will use _beacon_generate.py_ to pack the argument we want to display in the message box:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/f7d415dc1cfcd06fe467a30224986af3.png)

The BOF can now be tested:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/365f3b2c36a6f15abd894eb2d7b124c3.png)

Unfortunately, something does not appear to be working.  This is a good opportunity to introduce the debug build of COFFLoader which provides much more insight into what is happening as it tries to run a BOF.  The debug version of COFFLoader can be compiled on the Linux machine by running make debug within the COFFLoader folder:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/8527d5cb8c2b26f2737f7357bc29a27c.png)

Running our BOF again using the debug version of COFFLoader provides us with more information as to what the problem is:  `COFFLoader64Debug.exe go project1.x64.o bofargs.bin`.

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/da90775f5dc7e70e1b5540464484f2c5.png)

COFFLoader was unable to resolve the MessageBoxA WinAPI that is used by the BOF.  The same error is received when running the BOF in Cobalt Strike:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/16b46dae12ae1aa5048b96d45c018e5b.png)

This is far and away the most common error you will encounter when developing BOFs, but fortunately it is one easily remedied.  As was discussed in the [Background and Basics](https://www.zeropointsecurity.co.uk/path-player?courseid=bof-dev&unit=68273c95ca1f3cf7730387f5) section of the course, ==BOFs are not linked and any APIs called by the BOF must be resolved by the implant== (or COFFLoader in our case).  ==To enable the implant to do this, we need to provide it a hint so that it can locate== (and potentially load) ==the proper DLL and resolve the API in question==.

Create another new file in VSC in the project folder and name it _bofdefs.h_.  Place the following in the file and save it:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/f23b6d46843bd83dbb37bf0841079e38.png)

We include the windows.h file as it contains definitions for the data types that we use within the file (HWND, LPCSTR, etc).  Line 3 is where we build the prototype of the MessageBoxA WinAPI so that the loader may resolve it.  The chart below identifies each part of the prototype:

|   |   |   |   |   |
|---|---|---|---|---|
|**Import/Export**|**Return type**|**Calling Convention**|**Library and API name**|**Arguments**|
|WINBASEAPI|int|WINAPI|USER32$MessageBoxA|(HWND, LPCSTR, LPCSTR, UINT)|

- **Import/Export**:  ==This declaration indicates whether this function is one that the program is importing from another DLL, or one that it intends to export as a function available for others to call==. `WINBASEAPI` is a macro that expands to `DECLSPEC_IMPORT`, indicating that this function is one that we want to import for use within the program.
    
- **Return type**:  T==his data type is the return type of the API==. This value can be found in the syntax block of the Microsoft Learn page, which was included above.
    
- **Calling Convention**:  ==The calling convention of a function dictates how arguments are passed to functions==, ==where they are stored by the CPU, and how they should be cleaned up after the function is called==.  This value is very important!  T==he WinAPI use the== `==__stdcall==` ==calling convention, whereas APIs from the C standard library like== _==malloc==_ ==or== _==memcpy==_ ==use the== `==__cdecl==` ==calling convention==.  Arguments passed to ==__stdcall functions are cleaned from the stack by the callee==, or the function itself.  With ==__cdecl functions, the code that calls the function, or the caller, is responsible for cleaning the stack after the function returns==.  `WINAPI` is a macro that expands to __stdcall.
    
- **Library and API Name**:  ==This one is easy and is assembled by combining the API name with the DLL that it is found in.==  By referring to the requirements section of the Microsoft Learn page we can see that this API resides in _User32.dll_.
    
- **Arguments**:  This is an ordered list of the data types for each parameter required by the API.  These are pulled again from Microsoft Learn, though we can omit the directional indicator of the argument as well as the variable name and only provide the data type.
    

Paired with the function prototype on line 3 ==is a macro on line 4.==  This tells the program that any usage of ==MessageBoxA actually refers to== **==USER32$MessageBoxA==** and ensures that our program will ==use the API resolved by the loader instead of trying to refer to the normal (and unresolved) MessageBoxA WinAPI.==

Every API (be it a Windows or a C standard library one) used by a BOF must be declared in this fashion.  It should be noted that there is no requirement to place these within a header file called bofdefs.h, and that we are simply doing so for organizational purposes rather than functional ones.  If you wanted to, you could put these definitions in the main.c source file.

Finally make an additional include statement in main.c for bofdefs.h:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/23bb832ba2da6ae145e61164aaea9e49.png)

Recompile the code using:  `x86_64-w64-mingw32-gcc -o project1.x64.o -Os -c main.c`.

Running this new version shows our message box containing the arguments we packed earlier in bofargs.bin.

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/16a08026043ab935d9aaaf4b7ee4337b.png)

Dismissing the message box prints a message to the console demonstrating the use of the Beacon output API:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/225aa831b388f1e6a003058bba9c281b.png)

We have successfully created and ran our first BOF! 

Before moving on we will take a moment to create a Makefile for this BOF.  Including a build script with a project (be it a .sh script, a .bat script, a Makefile, or other options) is very helpful to others (and yourself!) given the often verbose compiler commands that must be used.  Create a new file in VSC in the project folder named Makefile and populate it with the following:

```makefile
BOFNAME := project1
CC_x64  := x86_64-w64-mingw32-gcc
CC_x86  := i686-w64-mingw32-gcc

all: clean x86 x64

x86:
    $(CC_x86) -o $(BOFNAME).x86.o -Os -c main.c


x64:
    $(CC_x64) -o $(BOFNAME).x64.o -Os -c main.c

clean:
    @ rm $(BOFNAME).*.o
```

This simple Makefile template will compile the BOF for both architectures.  More complex BOFs may require additional switches or parameters be provided to the compiler which we can add as needed.  This template can be reused by simply changing the BOFNAME variable. 

Once complete, run make in the directory containing the Makefile to compile the BOF:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/d392fa8577838f844374dec5441c48f4.png)