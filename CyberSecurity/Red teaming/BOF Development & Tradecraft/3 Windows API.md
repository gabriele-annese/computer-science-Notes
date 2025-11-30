
A resource that you will become very familiar with during this course is Microsoft Learn (Note: this resource was known as **MSDN**, or **Microsoft Developer Network**, prior to 2020). 

To get started, we will look at the [CreateFile](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea) API:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/c65ca7579089aab0b5d4c3230adb6a90.png)

What we care about the most in the above image is the grey syntax box.  This provides a concise summary of the API and its expected parameters.  Each API has a return type that indicates what will be returned to the caller of the API upon completion.  The return type is listed to the left of the API; in this case, **CreateFileA** returns a _HANDLE_.

What we care about the most in the above image is the grey syntax box.  This provides a concise summary of the API and its expected parameters.  Each API has a return type that indicates what will be returned to the caller of the API upon completion.  The return type is listed to the left of the API; in this case, **CreateFileA** returns a _HANDLE_.

The second value, _LPCSTR_, indicates the data type of the parameter.  Microsoft Learn provides a handy table describing each data type [here](https://learn.microsoft.com/en-us/windows/win32/winprog/windows-data-types).

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/fcbc83bbd2bbe7b63620b96c0388c6b7.png)

The last value, _lpFileName_, is a generic descriptor for what the parameter is actually supposed to contain.  They are often prefixed with shorthand abbreviations of the expected data type; "lp" means _long pointer_.  It should be noted however that the label _lpFileName_ is completely arbitrary; we could for example pass a variable named pizza as the first parameter, provided that is of the LPCSTR data type.

Taken all together, the first parameter for the CreateFileA API is a pointer to a string containing the path of the file (or file stream, directory, etc) that the caller wishes to open a handle to.  Each parameter required by the API is described in more detail under the syntax block:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/8b705fa2543c4eab2d916883f4c82389.png)

Some parameters are not required and can be set to _NULL_.  This can be seen in the _hTemplateFile_ parameter which is labeled **[in, optional]** to indicate this:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/8ef4849dcce7e22af74d594585895f35.png)

An APIs return value will also be described in more detail, and the **Remarks** section provides additional insight into the APIs usage.  CreateFileA is used for many things besides opening normal files, so its remarks section contains a lot more information than others (truncated in the following image):

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/ecf16f8d8173e5498bdce42fdcc50af6.png)

One more section deserves attention.  The **Requirements** table lists the minimum OS version required to use an API, as well as the DLL that the API resides in and the header file that must be included in a project to call the API:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/7b7eaa404266127300b4248cc22368ac.png)

For CreateFileA we see that we should include the _Windows.h_ header file.  Kernel32.dll is loaded into every process by default, but other APIs reside in DLLs that are not, requiring that the DLL be loaded by the process before the API may be used.  Depending on your target environment and the WinAPI in question, the Minimum supported client/server field may also be relevant; some APIs were introduced in newer versions of Windows and are thus unavailable on older versions.

It is also important to note that many WinAPIs have both an **A** and a **W** version, to include CreateFile:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/a2693d3c5e23f860062cfb85c435db67.png)

These suffixes indicate whether the API uses ANSI strings (CreateFileA) or Unicode strings (CreateFileW).  The two versions behave identically, with the difference between the two seen in the lpFileName parameter; CreateFileW expects a _LPCWSTR_ instead of a LPCSTR as in CreateFileA.  Looking at the data types resource from earlier we can see that the LPCWSTR data type is described as pointing to a Unicode string:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/3139f922b3d2d35237bba0a5c544b95e.png)

The sheer volume of information concerning a single WinAPI like CreateFile can seem daunting, but rest assured that using them is far simpler than might be anticipated.  The Windows API, and how to call them in BOFs, will be further fleshed out in later lessons.