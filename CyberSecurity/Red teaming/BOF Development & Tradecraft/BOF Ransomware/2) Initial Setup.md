On the Windows machine, create a new file in the _BOF_Course_ project by right-clicking **Source Files->Add->New Item...**.  Name the file _ransomware.cpp_ and copy the following contents into the file:

```c++
#include <Windows.h>
#include "base\helpers.h"

/**
 * For the debug build we want:
 *   a) Include the mock-up layer
 *   b) Undefine DECLSPEC_IMPORT since the mocked Beacon API
 *       is linked against the the debug build.
 */

#ifdef _DEBUG
#include "base\mock.h"
#undef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT
#endif

extern "C"
{
    #include "beacon.h"

    DFR(KERNEL32, GetLastError);
    #define GetLastError KERNEL32$GetLastError

    int go(char* args, int len)
    {
        return 0;
    }
}

// Define a main function for the bebug build
#if defined(_DEBUG) && !defined(_GTEST)

int main(int argc, char* argv[]) 
{
    // Run BOF's entrypoint
    // To pack arguments for the bof use e.g.: bof::runMocked<int, short, const char*>(go, 6502, 42, "foobar");

    bof::runMocked<>(go);
    return 0;
}

// Define unit tests
#elif defined(_GTEST)
#include <gtest\gtest.h>
#endif
```

We again need to change settings in the project to target this new BOF for Debug and UnitTest builds.  Right-click and select **BOF_Course->Properties**, select Debug from the Configuration dropdown, and finally in the debugging tab change the command to target ransomware.exe.  Note that if you wish to debug the x86 version you will need to select Win32 from the Platform dropdown and repeat these steps (but using Debug\ransomware.exe as the Command this time):

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/434447455e04599021a7927baaec767c.png)

Click **Apply** and then **OK** to close the window.  Next, right-click and select **project2.cpp->Properties**, select **UnitTest** from the Configuration dropdown and **All Platforms** from the Platform dropdown, and then set **Excluded From Build** to **Yes**:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/9d20e45ab9692a3c2f436641dca8a488.png)

With basic setup complete, we can move on and start coding.