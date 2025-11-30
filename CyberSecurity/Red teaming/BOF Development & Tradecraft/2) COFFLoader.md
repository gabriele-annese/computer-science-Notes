Before diving into developing BOFs we are going to take a moment to look at the primary mechanism we will use to run them, COFFLoader.  COFFLoader replicates how Cobalt Strike Beacons run BOFs and even includes functionality to generate arguments to pass to them.  We will run through a quick example to demonstrate how this works.

The _test64.out_ BOF that was moved to the Windows development machine during setup accepts a string argument and will print it to the console to demonstrate that the BOF was able to parse the argument and use it.  The Cobalt Strike Beacon API expects arguments passed to the BOF to be in a special binary format so that they may be successfully parsed and split out into separate variables at run time.  Cobalt Strike and other C2s have helper functions to accomplish this, but COFFLoader comes with a helper script, _beacon_generate.py_, to facilitate this.  It runs in an endless loop and allows users to add multiple arguments for use by the BOF.

BOF arguments are packed by the beacon_generate.py script in the order they are specified by the user!  You must specify the arguments in the order you wish to unpack/use them in a BOF!

Run the script with `python beacon_generate.py`:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/c5f4713cb22c6ff40cbcd5b3a7e09e9e.png)

BOFs can accept arguments of different data types.  Arguments are extracted by the BOF using different Beacon APIs based on the data type of the argument.  The [Cobalt Strike User Guide](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/cobalt_cobalt-strike_userguide.pdf) provides a handy graphic for this describing which Beacon API should be used to extract data of various types:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/1fa26889e2ee48240bfc53d555f16dca.png)

The following table maps the data types to the appropriate _beacon_generate.py_ command:

|          |                                  |                             |                     |
| -------- | -------------------------------- | --------------------------- | ------------------- |
| **Type** | **Description**                  | **Unpack With (C)**         | **beacon_generate** |
| b        | Binary data                      | BeaconDataExtract           | addFile             |
| i        | 4-byte integer                   | BeaconDataInt               | addint              |
| s        | 2-byte short integer             | BeaconDataShort             | addshort            |
| z        | Zero-terminated+encoded string   | BeaconDataExtract           | addString           |
| Z        | Zero-terminated wide-char string | (wchar_t*)BeaconDataExtract | addWString          |

We can generate an arbitrary string argument to use with the test BOF by using the _addString_ command in the Python script.  Given that we only intend to pass one argument to our BOF, we will next use the _generate_ command to write the packed BOF arguments to a file:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/0dc18a2eace4124445abdb0d9f558817.png)

We can then run the test BOF with COFFLoader by passing the _bofargs.bin_ file as an argument to it:
```powershell
.\COFFLoader64.exe go .\test64.out .\bofargs.bin
```

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/7464bb8c10271b05e75a333089f7d8fd.png)

Breaking down the arguments supplied to COFFLoader:

|              |             |                                   |     |
| ------------ | ----------- | --------------------------------- | --- |
| **Position** | **Value**   | **Description**                   |     |
| 1            | go          | The entry point of the BOF        |     |
| 2            | test64.out  | The BOF file to run               |     |
| 3            | bofargs.bin | The file containing BOF arguments |     |

The entry point of a BOF is defined on a per-BOF basis in the source code.  `Go` has traditionally served as the entry point (think a BOFs equivalent of a `main` function), but this is arbitrary and can be changed.  Specifying the 3rd argument (_bofargs.bin_) is optional; some BOFs do not expect any external arguments.

COFFLoader will be used extensively throughout this course to run BOFs without the need for a Beacon.