---
layout: post
title: Unpacking WalletBeastV2 (AutoIT)
---

The following post details the unpacking of an AutoIT malware, `WalletBeastV2`. The sample can be obtained on [Hybrid Analysis](https://www.hybrid-analysis.com/sample/64c5c4d4997c267f7ba0f362e507540e3f1cbd8b5b92b2a21ec90be6a4c39bcd?environmentId=100).

## Static Analysis

First step I always do is to open up the executable in `pestudio`. Let's see what information it can provide.

![pestudio](/images/2018-01-18-WalletBeastV2/Windows%207%20x64%20Malnalysis-2018-01-18-00-47-08.png)

The overview shows us that the file has a relatively high entropy reading which hints at encrypted and/or compressed data. It also shows us that the executable was compiled with Microsoft Visual C++.

![pestudio](/images/2018-01-18-WalletBeastV2/Windows%207%20x64%20Malnalysis-2018-01-18-00-47-22.png)

In the indicators section, it has some interesting potential functionality but one thing that stands out is that the file looks like it could be compiled with AutoIT. This may mean that some of these indicators may be false positives, especially with the VirusTotal detection rate.

![pestudio](/images/2018-01-18-WalletBeastV2/Windows%207%20x64%20Malnalysis-2018-01-18-00-47-29.png)

In the resources section, we can see that there is a `SCRIPT` file with an `AutoIT` signature. This data has an entropy reading of `8.000` which means it's most likely compressed.

![pestudio](/images/2018-01-18-WalletBeastV2/Windows%207%20x64%20Malnalysis-2018-01-18-00-49-53.png)

Finally, in the strings section, we can see a couple more strings referencing AutoIT. Note that there are many blacklisted strings, most of which come from the imports but they may just be false positives. Let's continue on...

Taking a look at the `SCRIPT` resource with `Resource Hacker` shows us some data with an AutoIT signature `AU3`.

![reshacker](/images/2018-01-18-WalletBeastV2/Windows%207%20x64%20Malnalysis-2018-01-18-01-01-03.png)

I can't really do anything with this right now because I am unfamiliar with how to deobfuscate the data directly. In this case, I've opted to use the tool `Exe2Aut` which is capable of reproducing the embedded script. Simply run `Exe2Aut` and then drag and drop the AutoIT-compiled program into it. It will also produce a `.au3` file to disk that contains the script.

![exe2aut](/images/2018-01-18-WalletBeastV2/Windows%207%20x64%20Malnalysis-2018-01-18-01-06-59.png)

The minimap on the right-hand side of Sublime Text shows that there is a large amount of text somewhere further down. Let's take a closer look at what that could be...

![sublime-text](/images/2018-01-18-WalletBeastV2/Windows%207%20x64%20Malnalysis-2018-01-18-01-11-28.png)

So here, we can see some hexadecimal bytes assigned to the `$ytzac` variable. The first two bytes are `4D5A` which is the `MZ` bytes that are present in every PE file. Let's extract all of this data and then dump it into a binary with a hex editor.

![hxd](/images/2018-01-18-WalletBeastV2/Windows%207%20x64%20Malnalysis-2018-01-18-02-10-04.png)

If we dump it in `dnSpy` and check the resources in the file, we can see a message from the author:

![dnSpy](/images/2018-01-18-WalletBeastV2/Windows%207%20x64%20Malnalysis-2018-01-18-02-29-47.png)

Looks like it's a Luminosity Link RAT. Running this file shows us a pop-up message box with this prompt to ask if the user wishes to install the program but of course, I'm going to politely pass up this generous offer. If we look at it in `pestudio`, it tells us that it has a relatively high entropy reading suggesting more packed files.

![pestudio](/images/2018-01-18-WalletBeastV2/Windows%207%20x64%20Malnalysis-2018-01-18-02-32-50.png)

However, I will not continue from this point onwards.

----

## Conclusion

If you wish to try to unpack the files in the RAT, feel free to do so! The sample is available at Hybrid Analysis as linked at the top of the post. Hope you've enjoyed the read and learned something! See you next time!
