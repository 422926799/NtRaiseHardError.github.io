---
layout: post
title: Unpacking Bitcoin Builder v4
---

The following post details the unpacking of the program `Bitcoin_Builder.v4.exe`. The sample can be obtained on [Hybrid Analysis](https://www.hybrid-analysis.com/sample/9d4ba009a5dd353d2177e32dbcbb525738e1f6d001bccc470576b90b0303975a?environmentId=100).

## Static Analysis

First, let's open the executable in `pestudio` and see what we have.

![pestudio](/images/2018-01-17-Bitcoin-Builder-v4/Windows%207%20x64%20Malnalysis-2018-01-17-14-54-50.png)

`pestudio` tells us that this file may have an embeded file within it...

![pestudio](/images/2018-01-17-Bitcoin-Builder-v4/Windows%207%20x64%20Malnalysis-2018-01-17-15-03-13.png)

Looking further reveals to us that there is indeed something here which has been detected with an executable signature. Upon that, it also seems to be holding some unknown data files labeled `DROPIN` and `EXEC` which is interesting as well. These names are probably quite self-explanatory in describing what information they might contain.

![pestudio](/images/2018-01-17-Bitcoin-Builder-v4/Windows%207%20x64%20Malnalysis-2018-01-17-15-03-45.png)

In the strings tab, we can see there are indeed references to API which handle the resources. Included here is also some debug information telling us who may have coded this application and the name of the project. `DarkCoderSc` is known as the author of the `Dark Comet` RAT as well as `Celesty Binder` which binds files together into the same executable file.

So since we have some interesting resources in this application, we'll open it up in `Resource Hacker` to see if we can get more information.

![reshacker](/images/2018-01-17-Bitcoin-Builder-v4/Windows%207%20x64%20Malnalysis-2018-01-17-15-15-53.png)

Opening the `APPLICATION.EXE` resource immediately shows us data with a PE file's signatures and structure `MZ` magic, the DOS stub, the `PE\0\0` signature and some common section header names respectively. We definitely want to have a look at this so let's save the resource by right-clicking `APPLICATION.EXE` in the tree view and selecting to save the resource.

![reshacker](/images/2018-01-17-Bitcoin-Builder-v4/Windows%207%20x64%20Malnalysis-2018-01-17-15-15-57.png)

In the `DROPBIN` resource, we can see the string `%TEMP%` which would indicate the environment variable that points to the user's temporary directory: `%USER%\AppData\Local\Temp`. This is likely where the binder will drop the bound `APPLICATION` file.

![reshacker](/images/2018-01-17-Bitcoin-Builder-v4/Windows%207%20x64%20Malnalysis-2018-01-17-15-16-01.png)

The `EXEC` resource shows `1` which probably tells the binder to execute the dropped file.

Now that we've extracted an executable from the binder, let's examine it in `pestudio`.

![pestudio](/images/2018-01-17-Bitcoin-Builder-v4/Windows%207%20x64%20Malnalysis-2018-01-17-15-28-50.png)

The overall view of the file shows us that it has a relatively high entropy at 7.002 meaning that it could be encrypted and/or compressed. Another thing to note is that this file is a C#/VB.NET executable as this will be required later on.

![pestudio](/images/2018-01-17-Bitcoin-Builder-v4/Windows%207%20x64%20Malnalysis-2018-01-17-15-28-28.png)

The strings gives us some clues tot he functionality of this program. From before, we can see that the entropy may have been a result of an encryption process as it uses the `System.Security.Cryptography` linbrary and there is a reference to a `CreateDecryptor` which may likely be what deobfuscates that unknown high-entropy data. There is also a reference to the `System.Reflection` library which might hint at dynamically loading another .NET application with the `Assembly.Load(pe_file_array).EntryPoint.Invoke()` method.
A couple of interesting strings as well. There is a debug string here that shows that the project may have likely been created using Microsoft Visual Studio 2012 with the default WinForms project with name of `WindowsApplication4`.

From here, we can decompile and analyse this file using `dnSpy`. I prefer this over `ILSpy` simply beacuse it can handle any potential obfuscation which would otherwise "break" `ILSpy`'s decompiler as well as having slightly improved features, not to mention the debugging capabilities which I can immediately jump into without having to load another application.

![dnSpy](/images/2018-01-17-Bitcoin-Builder-v4/Windows%207%20x64%20Malnalysis-2018-01-17-16-14-30.png)

On opening the file, we can see that the author has made an attempt at obfuscating the application's code. As I mentioned previously, `ILSpy` may have not been able to parse these characters and therefore be unable to show us the code. To help make sense of these random symbols, we can use `de4dot` to clean the names to produce something more easy on the eyes.

![de4dot](/images/2018-01-17-Bitcoin-Builder-v4/Windows%207%20x64%20Malnalysis-2018-01-17-16-16-47.png)

Once we have the cleaned file, we'll open it in `dnSpy` again.

![dnSpy](/images/2018-01-17-Bitcoin-Builder-v4/Windows%207%20x64%20Malnalysis-2018-01-17-16-16-03.png)

Ah, much better! We know there is something hidden in here so what I normally do first is to check the resources.

![dnSpy](/images/2018-01-17-Bitcoin-Builder-v4/Windows%207%20x64%20Malnalysis-2018-01-17-16-23-56.png)

So there is a file in here labeled `Encrypt`. If we attempt to examine this file, all we would get is scrambled data because it would be encrypted. So how can we obtain the original data? First, we'll need to see where in the code this resource file is referenced so at the bottom of the application's structure's tree view, expand `WindowsApplication4.My.Resources` and locate the `Encrypt` method like so:

![dnSpy](/images/2018-01-17-Bitcoin-Builder-v4/Windows%207%20x64%20Malnalysis-2018-01-17-16-24-20.png)

To see where _this_ code is referenced in the program, right-click the method name and select `Analyze` and at the bottom, there will be a panel that we can use to expand the call hierarchy of this method. If we follow the `Used By` tree, we eventually see it being called in the main method so let's jump there by double-clicking the reference in the tree view.

![dnSpy](/images/2018-01-17-Bitcoin-Builder-v4/Windows%207%20x64%20Malnalysis-2018-01-17-16-24-53.png)

On line 34, we can see where the call to retrieve the `Encrypt` resource lies. If we follow the assigned variable `encrypt`, we can see it being referenced on line 46 with a call to `GStruct0.rijndaelManaged_0.CreateDecryptor().TransformFinalBlock(encrypt, 0, encrypt.Length);` which is then assigned to the variable `byte_` which is most likely where we can obtain the unobfuscated data. Let's place a breakpoint here.

Before we extract the data, I mentioned something about using the `System.Reflection` library to dynamically load another .NET executable using the `Assembly.Load(pe_file_array).EntryPoint.Invoke()` method so let's see where this lies in the code. Assuming the obfuscated data is a .NET execuable file, we can trace the references of the `byte_` array and then successive variables until we reach the section of code where it executes.

![dnSpy](/images/2018-01-17-Bitcoin-Builder-v4/Windows%207%20x64%20Malnalysis-2018-01-17-17-07-04.png)

On line 64 we can see a reference to `byte_` and from there, it is assigned to `gStruct_0.memoryStream_0`. Down on line 79, it is used to assign some data to `gStruct.byte_0` which is used on line 90. The method `Versioned.CallByName` is quite a parculiar function and examining it on [MSDN](https://msdn.microsoft.com/en-us/library/microsoft.visualbasic.compilerservices.versioned.callbyname(v=vs.110).aspx), it tells us that it "executes a method on an object...". Sound suspicious enough? Let's see what the method name is stored in `GStruct0.string_0`.

![dnSpy](/images/2018-01-17-Bitcoin-Builder-v4/Windows%207%20x64%20Malnalysis-2018-01-17-17-15-18.png)

So it appears that there are three strings listed that are obfuscated with some funky characters but each of these passed as a parameter in a call to `Module1.smethod_2` which we can only assume is the decoding function. Let's check it out.

![dnSpy](/images/2018-01-17-Bitcoin-Builder-v4/Windows%207%20x64%20Malnalysis-2018-01-17-17-24-39.png)

What we can do here is copy the method (and the corresponding libraries too!) and create our own decoding program in C#.

![vscode](/images/2018-01-17-Bitcoin-Builder-v4/Screenshot%20from%202018-01-17%2017-33-34.png)

After executing the decoder, we can see the method names we were looking for!

----

## Dynamic Analysis

Let's get back on track and attempt to dump the obfuscated data. Press the `Start` button (or hit the `F5` key), let it run to the breakpoint and then step over it. This should be enough to deobfuscate the data and assign it to `byte_`. In the `Locals` pane at the bottom, right-click the `byte_` variable, select `Show in Memory Window` and then pick a memory view. We will be directed to a memory dump of the variable with the entirety of its data selected. We should also see a PE file structure with signatures to verify. Let's dump this by right-clicking the highlighted data and selecting `Save Selection`. Save it to disk, stop debugging (don't forget!) and let's examine it.

![dnSpy](/images/2018-01-17-Bitcoin-Builder-v4/Windows%207%20x64%20Malnalysis-2018-01-17-17-42-47.png)

Let's open it in `pestudio` to see what's up.

![pestudio](/images/2018-01-17-Bitcoin-Builder-v4/Windows%207%20x64%20Malnalysis-2018-01-17-17-43-42.png)

High detection rate (57/68) and keylogger traits. This might indicate that we're at the end of the unpacking.

![dnSpy](/images/2018-01-17-Bitcoin-Builder-v4/Windows%207%20x64%20Malnalysis-2018-01-17-17-44-13.png)

A lot of suspicious strings, some that verify keylogging functionality. We also have some very identifiable strings that may tell us what kind of malware it is AKA `Bladabindi` or `njRAT`. Let's confirm with the VirusTotal scans.

![dnSpy](/images/2018-01-17-Bitcoin-Builder-v4/Windows%207%20x64%20Malnalysis-2018-01-17-17-44-18.png)

Yep! Many detections saying `Bladabindi`.

----

## Conclusion

So I'll leave it at that. The sample is available to download from Hybrid Analysis at the top of the post. If you wish to see the internals of `njRAT`, you may continue onwards! Otherwise, hope the read was worth it and that you learned something. Until next time!
