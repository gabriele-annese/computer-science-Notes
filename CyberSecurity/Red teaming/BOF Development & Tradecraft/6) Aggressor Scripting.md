In this section we will write simple Aggressor scripts to integrate the BOFs written thus far into Cobalt Strike.

Aggressor is Cobalt Strike's scripting language and is often used to integrate BOFs into the Cobalt Strike client; unfortunately (or perhaps fortunately), it has not seen widespread adoption elsewhere.  This is probably due in part to the fact that it is a derivative language of [Sleep](http://sleep.dashnine.org/manual/), a "Java-based scripting language heavily inspired by Perl" that was developed Cobalt Strike's creator Raphael Mudge back in 2002.  While Aggressor can be very useful, if you are interested in writing BOFs that can be easily used cross-platform it is advisable to keep its role in the tool you are building to a minimum and offload as much as possible to the BOF itself.

There are two resources that are essentials for BOF development:

- The [Sleep manual](http://sleep.dashnine.org/manual/) – Aggressor, being based on Sleep, uses Sleep's data types, comparison operators, and branching and looping structures. 
    
- The [Cobalt Strike User Guide](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/cobalt_cobalt-strike_userguide.pdf) – This is the definitive resource on Aggressor-specific hooks, functions, and events.  
    

The third thing you will become very familiar with is reading other Aggressor scripts.  Very often you can find an implementation of what you are trying to do, or at least close to it, in another aggressor script on Github; some people have done some very complex things for it being such an obscure language.  Broadly speaking, an aggressor script needs to do the following in order to implement a BOF as a callable command within Cobalt Strike:

- Parse and validate arguments passed with the command
- Locate and read the BOF file
- Pack arguments to be sent to the BOF
- Execute the BOF

We also need to register the new command within the Cobalt Strike client.  We will accomplish all of this using Aggressor's `alias` and `beacon_command_register` keywords.  A basic Aggressor script implementing these steps that we will work from is:

```aggressor
alias project1
{
    local('$bid $barch $handle $data $args');

    # Assign arguments to variables for readability
    $bid = $1;
    $barch  = barch($1);

    # read in the right BOF file
    # 'script_resource' makes Cobalt Strike try and open the file specified
    # from the same directory as the aggressor script.

    $handle = openf(script_resource("project1. $+ $barch $+ .o"));
    $data   = readb($handle, -1);
    closef($handle);

    # Pack the arguments
    # Format specifier z for char*
    $args = bof_pack($bid, "z", $2);

    # Execute BOF
    beacon_inline_execute($bid, $data, "go", $args);
}

beacon_command_register(
    "project1",
    "Run the project1 BOF",
    "Extended help about the project 1 BOF goes here."
);
```

In the _project1_ folder on the Linux machine, create a new file named **project1.cna** and paste the above code into it.  The alias block is where the action (steps 1-4 outlined above) happens, while beacon_command_register is used to, as its name suggests, register the command for use with Beacon.  Note that the # symbol is the comment indicator in Aggressor, meaning that those lines are not interpreted as actual code.

Looking at the alias project1 block several local variables are defined, which is good practice to avoid unforeseen issues with other functions within Aggressor scripts.  The Beacon ID is always passed as the first argument to this function and is stored in the `$bid` variable.  The architecture of the Beacon running the command is similarly stored in `$barch` after calling the `barch` Aggressor function.  The script then continues to try and read the BOF file, using the $barch variable to select the correct version of the BOF (the Makefile compiles the BOFs as project1.x86.o and project1.x64.o).  Afterwards a single string argument (passed in as  an argument to the command in Cobalt Strike) is packed within the 
$args` variable using `bof_pack`, which is sent to the BOF when it is executed using `beacon_inline_execute`.

The beacon_command_register block is very simple.  The first string is the name of the command (so should match what follows the alias keyword), while the second is a shorthand description of what the command does.  The third string is where extended help information can be written, and is a good place to provide examples of how to run the BOF.

We will begin to modify this template by adding some additional variables and parsing out the arguments to the BOF.  The project1 BOF expects a string to display in the message box and an integer to echo back using BeaconPrintf, so we will create the `$message` and `$number` variables.  Since we always expect 3 arguments, we will add validation to display the help menu if the user does not provide two arguments to the command (remember the Beacon ID is always sent as an argument):

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/fbfb8c54ceea10d7e36b7d103b1fa66f.png)

We should probably also do some input validation on the $number variable; we are going to unpack the argument in the BOF as an integer, so we want to make sure the user provides a number for this argument.  We can do this using `!ismatch` and regex to specify that if the variable doesn't match the format of one or more digits (`\d+`) the command should abort:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/36bcd0af857cf0f88bc45427874e39b3.png)

Lastly we will modify the bof_pack call to use the `zi` format specifier and include our $message and $number arguments.  Remember that order matters when packing variables, as the BOF expects certain arguments in certain positions:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/1626c55a9d80603e3489869c1d2f367e.png)

We can flesh out the command help information within beacon_command_register as well:
```aggressor
beacon_command_register(
    "project1",
    "Run the project1 BOF",
    "
Command: project1
Summary: This command will create a message box on the target system
         in the current desktop session. The contents of the message
         box, as well as the appearance of the window, can be 
         customized by passing arguments to the BOF.

Usage:   project1  
         message to display     - The message to display in the message box. Wrap the message in
				  double quotes if it is more than one word.
         number to print        - The number to echo back using 'BeaconPrintf'

Example:
         project1 hello 10
         project1 \"Hey how are you?\" 15400       
"
);
```

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/fd55eb97db78d6f8d5b1b173cda2038c.png)

How much you choose to provide in the way of instruction or help info for a command is entirely up to you.  After saving project1.cna, import it within the script pane of Cobalt Strike:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/3739147cc7b251da560a4f95df8542d9.png)

We can now run our command through Beacon.  Typing **project1** and hitting **enter** will print the extended help menu since we didn't provide the required 3 arguments:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/399809254a21f08a04040687fcc7c773.png)

Trying again and this time providing arguments succeeds, creating a message box with our text on the target machine:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/9f77941dcc77c0835ded275bcf7c4dd2.png)

After clicking OK on the message box the BOF completes and Beacon returns a message containing our number:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/83b1129ab06292be62266c87c5de20ce.png)

We now have a working Cobalt Strike Aggressor script for the first project!  Making the second one is going to be very simple, requiring only minor tweaks to the script we just completed.  Create a new folder _project2_ on your Linux machine and within it create a copy of project1.cna named project2.cna.  Copy over both the x86 and x64 version of the project2 BOF from the Windows machine to this folder too (`BOF_Course/release/project2.x86.o` and `BOF_Course/x64/release/project2.x64.o`):

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/3a8e5343a4f03174dd69f87168acb9e5.png)

Next we'll begin to modify the Aggressor script for project2.  We can begin by using the editor's find + replace feature to change all instances of project1 to project 2.  In contrast to project1, which requires two arguments, project2 optionally accepts one.  We will update the local variables and the logic that validates the number of arguments provided:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/c0800680481a945d020537f7b87d96c6.png)

We could optionally add input validation to ensure that the string provided is in the proper format for Windows file paths, but will forego that task given the simple nature of the BOF and what it does with the provided argument.  To this end, we will remove the input validation block ($number !ismatch '\d+').  Because the argument is optional, we will need to wrap the bof_pack call in an if statement so that it only runs if an argument was provided:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/36a4427126a7b4e2b692516bf57336b7.png)

The beacon_register_command can be updated as well:

```aggressor
beacon_command_register(
    "project2",
    "Run the project2 BOF",
    "
Command: project2
Summary: This command will retreive the hostname of the computer,
         the username of the current user, and optionally whether 
         a specified file exists or not. 

Usage:   project2 [path to validate]
         path to validate     - The absolute path of the Windows file that
                                should be checked for existance 

Example:
         project2
         project2 C:\\Windows\\System32\\Kernel32.dll
         project2 \"C:\\Program Files (x86)\\Internet Explorer\\ieinstal.exe\"
"
);
```

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/faa687c1aab7a801d6372214047c86fb.png)

After saving, the Aggressor script can be loaded in Cobalt Strike:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/8514db06786c364ffa70c74f8bcf677b.png)

Running the BOF with no arguments succeeds:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/073c8b35188f63581ebbc133048ea81c.png)

Similarly, providing the BOF with either a real file or a fake file returns the expected output:

![](https://lwfiles.mycourse.app/66e95234fe489daea7060790-public/756b05d6d692eb37979319fc2dfd1b80.png)

The Aggressor scripts developed in this module were fairly simple; they can quickly become more complicated depending on the nature of the BOF or tool.  We will continue to explore Aggressor scripting in each of the practical examples within the course.