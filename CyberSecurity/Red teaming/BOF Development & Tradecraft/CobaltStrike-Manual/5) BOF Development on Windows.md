In this module we will explore the Visual Studio BOF template provided by the Cobalt Strike team.  This template does a lot of heavy lifting when it comes to BOF development on Windows, so it is worth getting comfortable with how it works.  Looking in the Solution Explorer on the right-hand side we can see a few things that look familiar and a few that don't:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/15fc2fcc8d09f5f21ea1febe8557bd0d.png)

There is a _beacon.h_ file in the **Header Files** folder that matches the one we added on Linux, and under **Source Files** we find _bof.cpp_ which is the VS template's equivalent of _main.c_.  The remaining unfamiliar folders and files are used to facilitate capabilities offered by the three different solution configurations set up within the VS template.  These configurations are selectable from the solution configuration dropdown menu and alter the behavior of the solution when it comes to compiling and running the code:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/115a05373052eb626cabedef170c2478.png)

- **Debug**: The BOF will execute in the VS debugger using some helper functions, allowing for easy testing.
    
- **Release**: Produces a normal BOF ready for use with COFFLoader or a C2 framework.
    
- **UnitTest**: Uses user-defined unit tests to determine if a BOF functions as intended.
    

Selecting a specific solution configuration changes several compilation-related settings within the project. For example, the UnitTest configuration uses both the `_DEBUG` and `_GTEST` preprocessor directives:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/8eb3df3399c8c7cf84f34ce0f382d766.png)

Debug unsurprisingly also uses the _DEBUG directive, with both it and the Release configuration compiled using nmake.  The use of these preprocessor directives changes which code is compiled in the final executable.  This is illustrated in the following image, where the code contained between lines 44 and 54 is only included when the DEBUG flag is defined and the GTEST flag is not defined, as is the case with the Debug configuration:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/537b4f0d290cbf25415b47d74fda0438.png)

Similarly, the code block between lines 54 and 69 is only included if the GTEST flag is defined as in the UnitTest configuration.  Switching the solution configuration option will brighten or dim code to convey whether it is included in the selected build or not; the above image of the Debug configuration shows that the main function (line 46) will be included whereas TEST (line 57) will not.

The functionality of the example BOF included with the VS template is extremely simple; it calls [GetSystemDirectoryA](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) to retrieve the path of the system directory and then prints the value using the BeaconPrintf Beacon API.  Notably, while we wrote the Linux BOF in C, the VS template instead uses C++.  The Cobalt Strike team describes their reasons for using C++ in the [Simplifying BOF Development](https://www.cobaltstrike.com/blog/simplifying-bof-development) blog:

We have chosen to use C++ for our template primarily because it offers features that help improve DFR [Dynamic Function Resolution] declarations. We can also leverage powerful features built-in to the C++ language, such as templates, classes and compile-time expressions etc. Many use cases already exist for these features, such as applying compile-time string obfuscation, as demonstrated by Adam Yaxley [here](https://github.com/adamyaxley/Obfuscate). Additionally, there is also the added benefit that it is trivial to port the significant number of existing C BOFs to use it.

Henri Nurmi

**DFR** refers to the WinAPI declarations that we placed in _bofdefs.h_ during the last module.  The VS template's DFR macro greatly simplifies this process, no longer requiring us to look up a WinAPIs syntax to define its prototype.

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/eef992c7b62ebbbcbead196d047e9578.png)

Line 19 shows the use of the DFR macro to resolve the GetLastError WinAPI.  Looking at the definition of this macro within _Header Files/base/helpers.h_, we see that it makes use of the decltype specifier which extracts the type of the WinAPI automatically:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/51186de1f04e8ac5597e9198383ff121.png)

In using the DFR macro we achieve the same result as writing out each API's prototype long-form, but with less hassle.  Note that we still must create a macro to correlate the use of GetLastError with `KERNEL32$GetLastError` as shown on line 21.  Another macro, `DFR_LOCAL`, is also available to be used for API resolution.  This macro works in a similar way except it is restricted in scope to the function in which it is declared, and further does not require the macro:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/555c47276880a364c03fa1d7a4f37c57.png)

Which macro you use (and when) is ultimately your choice; logically it might make sense to declare APIs used in multiple functions using the DFR macro, and APIs that appear in only one function using DFR_LOCAL, but others may prefer to declare all APIs using the global DFR for organizational purposes.  To better illustrate the capabilities of the VS template, we can test out the BOF by selecting Debug within the solution configuration drop down menu and then clicking Local Windows Debugger just to the right of it:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/9636c2d4fadf6950c1f4c2381183afff.png)

Doing so will open a VS Debug prompt and print the result of running the BOF to the console:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/73a1f1398c057ca6e334c52e38e3581d.png)

The convenience that the VS template's ability to run and test BOFs provides is hard to argue; we can test our BOF without involving an external entity like COFFLoader or a Cobalt Strike Beacon. 

This brings us to the third (and probably more unfamiliar looking) solution configuration, UnitTest.  Unit testing involves writing and running specific tests to ensure that individual parts of a program function as expected.  They provide a means by which to quickly identify issues introduced to code either during its initial writing or perhaps more importantly on subsequent updates and revisions.  A number of different unit testing frameworks exist, but the VS template uses Google's framework, GoogleTest.

The single unit test defined for this BOF is very simple. It runs the BOF using the runMocked helper function and stores any returned output in the got variable (which is of type `std::vector<bof::output::OutputEntry>`).  A second variable of this same type, expected, is populated with the expected output from the BOF should it run successfully.  The sizes of the got and expected variables are then compared to see if they are equal (which is the case when the code behaves as expected) using the `ASSERT_EQ` macro.  As a final check, the `ASSERT_STRCASEEQ` macro is used to ensure that the output from running the BOF matches the desired output defined in expected (Note that the comparison done by ASSERT_STRCASEEQ is case-insensitive):

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/08c2884d18cb155f982fe85767ef146e.png)

By selecting **UnitTest** from the configuration dropdown and then clicking **Local Windows Debugger** we can run the unit test and see if our code functions as expected:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/cb70981ff8193e95aa56ce147329eafb.png)

The test succeeds.  This test works well for this BOF, but pretty quickly falls apart as you look to more complex behavior; for example, if the BOF instead retrieved the list of installed hotfixes on a machine, hardcoding in the list of hotfixes installed on the specific machine the unit test runs on doesn't make sense and is liable to throw all kinds of false positive errors when a new hotfix is installed (or when the unit test is ran on a different machine).  We will explore different ways to write and utilize unit tests later, but in the interim a full listing of available tests within the GoogleTest framework can be found here.

One vital thing to note is the use of the `extern "C"` linkage statement on line 16 in the following image.  This instructs the compiler to use C linkage for the code contained within the curly braces, as opposed to C++ linkage which mangles function names and causes issues when trying to invoke a BOFs entry point or Beacon APIs.  To demonstrate this we will move the go function outside of the extern "C" block and compile the Release version of the BOF by selecting Release within the build configuration drop down menu and then navigating to **Build->Build BOF_Course** just above it (or by using the **Ctrl + B** keyboard shortcut): 

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/f6936129b7f4be924b493d9a5bd44efb.png)

In the Windows search bar type in native and open the Visual Studio x64 Native Tools Command Prompt:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/03586f27535f04eae1fee0b1dc557341.png)

We can use the VS utility `dumpbin` to display the symbols within the BOF and see that that the go entry point (as well as GetSystemDirectoryA) has had its name mangled by the C++ compiler:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/34cfb0338a4d98132c28aea24d356df1.png)

Trying to run this BOF with COFFLoader results in an error due to the name mangling:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/eb16267e99e830dc18c71cbf200dca96.png)

There are some cases where it may be desirable to write the body of the BOF outside of the extern "C" block.  Certain elements of the Windows OS are easier interacted with using C++ than C, like Component Object Model (COM) objects.  In other instances, you may be trying to port a tool written in C++ to BOF format which would be made easier by leaving the existing C++ code in place.  Fortunately, this can be accomplished fairly easily.

We can prevent the mangling of the go function by declaring it (but not implementing it) within the extern "C" section.  Additionally, by replacing any usage of DFR_LOCAL with the global DFR macro within the extern "C" block we can avoid APIs having their names mangled:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/514fa0c103b75fb2a5d2cd23dff27eb2.png)

Running dumpbin again after recompiling shows that the symbols are no longer mangled:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/a0aff0f1e57cad65468be9b076cfd5a2.png)

COFFLoader is additionally now able to run the BOF successfully:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/5abe2fd89d8faa451a8afbbd3a76600c.png)

To better understand what has been covered thus far we will create another simple BOF, this time with the following goals:

- Resolve and print the hostname of the machine
    
- Resolve and print the username of the current user
    
- Check to see if a file provided as an argument to the BOF exists or not
    

Handily, the VS template supports multiple BOFs within a single project, so we can start by right-clicking Source Files and selecting **New Item…** from the **Add** sub menu:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/5014721ee520169b47487763313ecd75.png)

Enter _project2.cpp_ as the name of the new file and then click **Add**:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/6ba229850699898168a5e9c3127aa0a0.png)

There are a few configuration changes we need to make when working with multiple BOFs within a single project.  The first involves changing the target of the local debugger.  Right-click the _BOF_Course_ project in the solution explorer and select **Properties** to open the project configuration properties dialogue.  Select the **Debug** build from the configuration menu and then under the Debugging tab change the _Command_ field from _x64\Debug\bof.exe_ to _x64\Debug\project2.exe_:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/2f89950a71f32762e4b7a705e651bdb8.png)

Click **Apply** and then OK to save the setting and close the dialogue.

The second change we must make involves the **UnitTest** solution configuration.  While the Debug build is set up to compile each source file as its own executable, UnitTest is not, so we will run into multiple-definition compilation errors when trying to compile and run this configuration.  This can be resolved by right-clicking _bof.cpp_ and selecting **Properties** to open the source files property pages.  Select the UnitTest build from the configuration menu and then under the **General** tab set the **Excluded From Build** field to **Yes**:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/49059180e0b5e3969e46afdb01792f4c.png)

Again click **Apply** and then **OK** to save the setting and close the dialogue.  This will apply a red circle icon to the bof.cpp source file indicating that it is currently excluded from the build process.  This exclusion can be toggled off again by repeating the above steps and either clearing the Excluded From Build field or setting it to No.  Both of these steps must be completed each time you wish to change the BOF you are working on within the project.

We will begin coding in _project2.cpp_ by copying over the original contents of bof.cpp, as it provides a good foundation from which to start.  We will remove the specific code/APIs used bybof.cpp as well as the unit test so that we are left with a blank template from which to work.  We will again use extern "c" to wrap the include statement for _beacon.h_ as well as our eventual DFR statements, and we will include the go function within this block as well since we do not intend on using any C++ specific code:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/7eb761cb46b9abf6a1cc66e75858e307.png)

Our first objective is to retrieve the hostname of the machine.  A quick Google search for "winapi get hostname" brings us to the [GetComputerNameA](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getcomputernamea) page on Microsoft Learn which looks a lot like what we want.  The DFR macro is used alongside a define statement to enable the use of GetComputerNameA.  We will do the same for GetLastError as we will make use of it should we encounter an error:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/7e23b9533327a5d52a75e77e9b80a4f5.png)

We will create a new function within the extern "C" block called GetHostname, in which we will declare and define several variables for use with GetComputerNameA.  This API returns a BOOL, so we will have the GetHostname function do the same.  In terms of parameters, GetComputerNameA accepts a pointer to a buffer and a pointer to a DWORD containing the length of the supplied buffer.  Following the guidance of its Microsoft Learn page, we declare the buffer to be of length `MAX_COMPUTERNAME_LENGTH` (which is a macro that expands to 16) + 1.  We can finally call the API and will use the result to print either a success or an error message as well as return the value to the caller of the GetHostname function.  In go we will call our new function:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/68f30be1a93be37202724794b213bcda.png)

As a quick aside, remembering the arguments and the order they are in for a given WinAPI can be tricky.  When writing a normal program in which the WinAPI is called the standard way, one can simply right-click it in VS and select Peek Definition to display its definition in a pane within the code window.  Our define statements (lines 21 and 24 above) override the original definition of the APIs and prevents us from using this convenience; however by temporarily commenting out the define statement in question, we can again right-click and peek the definition of the API to remind ourselves of the order and format of expected parameters:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/556042081237a99c10447a88aead277f.png)

With the GetHostname function complete we can test the BOF by uncommenting the line above, switching to the Debug configuration, and running the Local Windows Debugger:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/b2bae22cdb2332f2bd0a8551f01c4c7c.png)

Now that the GetHostname function is written we will take a moment to write its unit test. The test is again very simple, but offers an opportunity to get more practice in. As both the Microsoft Learn page and the Peek Definition window show, GetComputerNameA returns a non-zero result if successful. We can make a unit test for this like so:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/c6ce54c10ca74f75a951d2e4e2b72e34.png)

The ASSERT_NE test runs the GetHostname function and compares the return result against 0. A successful test is observed when the two do not match (NE means not equal).  Running the test succeeds:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/627e98af43c9d7ee04069520a385a34f.png)

For the sake of demonstration, we can intentionally cause the test to fail by modifying the _dwHostnameLen_ variable within the GetHostname function:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/797c3b8c91e466d78c9417841924cdf7.png)

The GetComputerNameA call now fails because we told the API that the supplied buffer can only hold one character.  We can confirm this by looking up the meaning of error 111 which was returned by GetLastError in the list of Windows error codes:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/f1cf4bb646d6b9078ae836e0faf3b308.png)

After reverting the change to dwHostnameLen we can proceed to our next objective.  To resolve the username of the current user we will use the GetUserNameA WinAPI.  One useful suggestion from the Microsoft Learn page is that the buffer supplied to GetUserNameA should be of length UNLEN + 1, and that the `UNLEN` macro is defined within _lmcons.h_.  We will add an additional include statement to project2.cpp so that we can use this macro (which expands to 256) and add our DFR statements for GetUserNameA as well:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/00a70fe8460738af87052f947b18b23d.png)

Note that the GetUserNameA WinAPI is an export of Advapi32.dll, not Kernel32.dll, so ADVAPI32 is used in the DFR statement.  As a reminder, this information can be found in the Requirements section on the Microsoft Learn page.  For the Debug configuration we must additionally use a pragma directive to link advapi32.lib so that we can resolve GetUserNameA at runtime.  Normally Beacon or COFFLoader will load any DLLs required by the BOF that are not already loaded by a process, but in the VS template Debug and UnitTest builds we must explicitly instruct the compiler to link against the required DLL.  [Stack Overflow](https://stackoverflow.com/questions/3484434/what-does-pragma-comment-mean) has a very helpful and concise explanation of #pragma comment directives that explains:

#pragma comment is a compiler directive which indicates Visual C++ to leave a comment in the generated object file. The comment can then be read by the linker when it processes object files.  
  

#pragma comment(lib, libname) tells the linker to add the libname library to the list of library dependencies, as if you had added it in the project properties at Linker->Input->Additional dependencies

Following the same pattern as before, we will create a GetUsername function and define the variables required to call the API.  It coincidentally has the exact same type definition (returns a BOOL, expects LPSTR and LPDWORD parameters) as GetComputerNameA, so our GetUsername function will end up looking very similar to GetHostname:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/3a02c885bc02540fe45f2f80a451f745.png)

Running the Debug configuration we see our username successfully printed to the console:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/ae6709c3363fac306ac8dc30e620843d.png)

The unit test for GetUsername will also be effectively identical to the one we created for GetHostname:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/35e2d77464bfdaabdd070b25bc100bb0.png)

We again define a successful call to GetUsername as returning a non-zero value, and running the UnitTest build shows that our new test passes successfully as well:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/96e4331c89d5e632e46442dbc7027400.png)

We can now move on to the final objective for the BOF, checking whether a user-specified file exists on the system.  A quick google search for "winapi check if file exists" later and we have a viable candidate in PathFileExistsA.  We will repeat the steps from before and include the APIs header file (shlwapi.h), add a pragma directive to include Shlwapi.lib in the Debug build, and write our DFR statement: 

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/167291b81da87172c988a36071358cfb.png)

More for the sake of further demonstrating unit testing than anything, we will create another simple function CheckFileExists that calls PathFileExistsA:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/298a3ca2d76e6ab3dbc682f13a7e1551.png)

Calling the function is where things get a little more interesting, as is now expects a user-supplied string.  This will be provided as an argument to the BOF, so we will need to make use of the Beacon APIs to unpack and parse the BOF arguments:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/c02fdebe245a5f1c9abc9ed5d4625005.png)

Switching to the Debug configuration, we now need to supply an argument to the runMocked function within main in order to emulate how an argument would be passed to the BOF when ran in an implant.  We want to pass a string as an argument to the BOF, so we will use `const char*` as the variable type and pass in _c:\\windows\\system32\\kernel32.dll_ as the file to search for.  Note the double backslashes, which are necessary because backslash is the designated escape character in C and C++:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/371ec7b0efe5c003b6badd1ca5103290.png)

Running the Debug build succeeds:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/cad250104869a6084456f7b66797c7ba.png)

The unit test for this function gets a little bit more interesting because there is a user-supplied parameter involved.  We can write tests for both successful and unsuccessful calls to the function:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/7fdf721253c92fb2db4d0113e2df7a02.png)

CheckFileExists returns a non-zero value when successful, so the ASSERT_NE test passes when a valid file is specified.  The ASSERT_EQ test passes when an invalid file is specified, resulting in CheckFileExists returning 0.  Running the UnitTest build shows that all tests pass:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/3f8a9eae5775747891ff2a351d8e23f3.png)

We have successfully written and tested our BOF!  Getting a BOF to run successfully is a great feeling, but the work isn't over yet.  To design reliable and effective tooling, we must anticipate potential points of failure and build safeguards to address them.  While you wrote and understand this BOF, it may eventually be used by someone else (whether that is someone else at your job/company or random people on the internet if you publish it) who does not; documentation and stress testing go a long way towards providing a positive user experience.

To dig into this, what happens for instance if the BOF is ran without any arguments at all?  We can test this by removing the arguments from main and running the Debug build: 

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/b04cbee256dc37c47f72b0eace853d5a.png)

Doing so results in an access violation; this in truth has more to do with a limitation in the VS template than an issue in our code:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/b3fd2a724438447e8593306db7dabc1e.png)

The access violation exception is thrown in the BeaconDataInt function; this might initially seem odd given we did not call this Beacon API, but it is invoked by BeaconDataExtract which we did call.  BeaconDataInt fails because `parser->buffer` is a **null pointer**, which throws an exception when it is dereferenced on line 177.  We can resolve this error by adding an _if_ statement to only proceed if `parser->buffer` is not equal to `nullptr`:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/5207e15b9c1671968f7101276e74e702.png)

Note that this same issue exists and must be fixed in BeaconDataShort.  Both of these Beacon APIs return a number, so for this reason we will return 0 if a null pointer is encountered.  After making the changes make sure you clean the solution using **Build->Clean BOF_Course** and then rebuild it using **Build->Build BOF_Course** or **CTRL + B**.  Though we edited mock.cpp, the solution isn't configured to recompile the project unless it detects changes in _project2.cpp_.

It should be reiterated that the issue we just addressed was a limitation in the VS template, not a direct problem with our BOF.  Both COFFLoader and Cobalt Strike Beacons can successfully use BeaconDataInt and BeaconDataShort when given null pointers without issue.  Running the Debug build again shows that our BOF runs successfully, though we are still calling CheckFileExists without providing an argument:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/f9a58fc431a5011c56192452a95d3dd1.png)

We can easily implement logic in go to ensure the function is only called when an argument is provided by adding an if (fileToCheck) conditional as seen on line 90:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/0c18f58ac956219b0f35d35c9bba7161.png)

It would also be really nice if we could create a unit test for the entire BOF, allowing us to pass arguments to the BOF itself instead of only being able to do so via unit tests for specific functions (like CheckFileExistsTest).  Referring back to the example Test1 from _bof.cpp_, we can see that the test does run the BOF by calling `bof::runMocked<>(go)`, but that the output or return value from this call is the Beacon output (of type `std::vector<bof::output::OutputEntry>`), not any sort of status code that we could use to discern success or failure:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/5ba37496910cd748de5ed2e1d2899487.png)

This seems like a change worth making, so we will take a second to further customize the VS template to support this functionality.  We will begin by opening _Header Files/base/mock.h_ from the solution explorer and taking a look at the **bof::runMocked** function:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/d3d08bfe95cbeb6975ea27a3650e8d94.png)

This is a template function that packs provided arguments before calling the entry point of the BOF.  Output from the BOF is retrieved by calling **bof::output::getOutputs** in the return statement.  **getOutputs** returns a `std::vector<bof::output::OutputEntry>`, which is accordingly the return type of the **bof::runMocked** function.

Ideally we could also return a status code alongside the Beacon output entry (which is the go function) is called at line 165, but because it is defined as a void function nothing is returned when it is complete.  Making go return an int instead of void will be dealt with in a second, but for now we can declare a struct that will be used as the new return type for the **bof::runMocked** function, **bof::output::ReturnData**:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/ad759f31c2d5f26bc36d651ef40c7513.png)

This struct contains a variable of the same type as _bof::runMocked_'s original return type (_outputBuf_), as well as an int that will contain the return value from go (_returnVal_).  In the _bof::runMocked_ function we can now change its return type to be that of the new struct.  We'll also alter the body of the function to store the return value from calling the BOF's entry point within the struct, alongside the BOF output retrieved by calling _bof::output::getOutputs_:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/28311c2e8eec45d9d1dc4d0ca8d9f19b.png)

Back in _Source Files/project2.cpp_ we can change the return type of go to int, and also add logic that causes the BOF to return / not carry out additional tasks if one of the function calls fails.  Nothing catastrophic would happen if GetUsername were called after GetHostname fails, but other BOFs could certainly crash if for example they attempted to use a buffer that was not successfully allocated earlier in the program.  The updated go function looks like this:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/a4d462dd1a2f70c6000b3c3bad189ee9.png)

Updating the bof::runMocked function definition within _mock.h_ will cause _bof.cpp_ to throw an error when it is compiled.  This can be resolved by updating the go function within bof.cpp to return int and by adding a return 0 line at the end of the function as shown in the prior image.  Remember to also update the go declaration within the extern "C" block as well.

We can now write unit test for running the entire BOF, with three specific tests:

- A valid file path is supplied
    
- An invalid file path is supplied
    
- No file path is supplied
    

The ASSERT_EQ test will be used to compare the return value of go against 0, which indicates "success".  These tests will be organized together as goTest and can be written like so:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/7d9ddbbc3971526237565da45a702a3a.png)

Running the UnitTest build shows that one of our tests failed:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/075b0ddbabb6941315fe4b79ff79f225.png)

It looks like the second test case (providing an invalid file) reports as a failure; this is because PathFileExistsA returns FALSE when a file doesn't exist, causing go to return -1.  The WinAPI determining that a file does not exist is a valid outcome, so really what we should do is add logic to the CheckFileExists function so that it only returns FALSE if the API fails for a different reason:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/669d6f9c263adde817e85f27e9df6ab2.png)

Because of this change we must revise the logic of CheckFileExistsTest, which should now report a non-zero (TRUE) return value for both a valid and an invalid path:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/946be3c5962e8222d4726cbcfba30fb0.png)

We can get more granular with CheckFileExistsTest by looking for the specific Beacon output messages associated with a file existing or not existing.  This is similar to what Test1 from _bof.cpp_ did, except in this case we must be a little more manual with the VS template helper commands since we are running a specific function instead of the entire BOF.  This includes resetting the BOF output buffer before each test, retrieving the Beacon output after calling the function, and then comparing the runtime results against the expected output:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/8784d6dca5ab7a61023ec45852dcc138.png)

This unit test now ensures that, despite returning the same status code, the CheckFileExists function correctly distinguishes between files that exist and those that do not.  Running the test again succeeds:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/2d5592a6c3559a923b122a182d9cce88.png)

How you implement unit tests is ultimately your decision; this BOF probably didn't need this many unit tests given how simple it is, but it was a good opportunity to explore how tests can be written and implemented should they be desired.

After switching to the Release configuration and building the project it can be tested using COFFLoader.  We will create packed arguments for the BOF using the _beacon_generate.py_ script and then provide the file containing the arguments to COFFLoader:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/335b39484c648734acbd479007118617.png)

COFFLoader prints the Beacon output without new line characters so the formatting doesn't look great; in an implant however each print statement will be separated:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/197163039bd1b67403020e829826a42e.png)

If it really bothers you, you can add newline characters (`\n`) to the end of each BeaconPrintf call to make COFFLoader's output cleaner.

The last thing to check is that the x86 version of the BOF works as well.  There shouldn't be any issues, but strange things can happen when you are compiling object files using all kinds of strange compiler switches.  It bears repeating that due to the nature of the VS template, there are significant differences in building for Debug or UnitTest and Release.  In this case the x86 Debug build works fine, but running the Release build in _COFFLoader32.exe_ results in a crash:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/7c67089852cd0692d8b22c2c9d2f131e.png)

Running the same BOF in a Beacon reveals more information:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/6fb46eb2171f626788e886c563da82d7.png)

This is strange, as we don't use `memset` anywhere in our code, and the x64 version of the BOF doesn't have the same issue.  Comparing the x86 and the x64 versions using dumpbin (open both a x86 native VS command prompt and an x64 one), we see that the x86 version has an added symbol, `_memset`:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/a84c7435ee125e504fd696fb1794adf0.png)

To skip to the end of a lengthy research and troubleshooting session, in the GetUsername function we create a CHAR array usernameBuf and fill it with null bytes by setting it equal to `{ 0 }`.  For larger structures, the x86 compiler accomplishes this by inserting a call to memset, which poses a problem because linkage will not occur in order to facilitate this.  We don't encounter this problem in the GetHostname function because the CHAR array initialized there is only 16 bytes in length.  This is an annoying problem to have spent several hours identifying and trying to fix, but we can resolve the issue by simply making another DFR statement and using memset ourselves:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/caa2321f86d129b9d6008d9d1ad5ac96.png)

The x86 version now works, and for good measure we will verify that the x64 version still works too (which it does).

The VS BOF template provides a lot of functionality and "nice-to-haves", but ultimately writing BOFs on Linux or Windows is a personal choice, and the methodology displayed here is certainly not the only way to accomplish the task.  Some BOFs may be easier to develop on one platform versus another due to the specifics of the project, but at the end of the day both are viable options.  The practical examples in the rest of this course will be divided so as to demonstrate development of operation-ready BOFs on both platforms.