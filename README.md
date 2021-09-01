# PE-Appropriator
A static reversal tool for revealing PE's contained in a segment of memory
#
The PE appropriator recurses input memory from disk to find a signature of the DOS headers e_magic. If the appropriator finds a 'MZ' signature then it parses the PE to obtain the image size so that it can then dump the PE out of the memory context for static & dynamic analysis. This tool is great for revealing possible malware hidden inside trojan proccesses but can also be used to obtain restricted resource from a process.

It also has the ability to dump multiple images from a single context, the signature has been extended an extra two bytes x90, x00 so that the signature finder doesn't find random 'MZ' characters.

This relys on the developer not removing the e_magic from their image buffer themselves and replacing it at runtime. Otherwise the signature scanner will not find the header. If changes were to be made in the future id make an option to dump active processes, this would make the usage of the tool much greater because it would allow for streamed payload to be dumped once its in memory.

The project could also be made to be injected into another processes context where it could hook imported heap allocation functions and scan each allocation made at runtime to see if it contains a PE header, this would be alot more effecient, faster and potentially more effective against better equipt methods of handling valuable payload.

![](https://github.com/j7cb1/PE-Appropriator/blob/main/readme/Usage.PNG)

![]( https://github.com/j7cb1/PE-Appropriator/blob/main/readme/MS-DOS%20header.PNG)
