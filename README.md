# PE-Appropriator
A static reversal tool for revealing PE's contained in a segment of memory
#
The PE appropriator recurses input memory from disk to find a signature of the DOS headers e_magic. If the appropriator finds a MZ signature then it parses the PE to obtain the image size so that it can then dump the PE out of the memory context for static & dynamic analysis.

![](https://github.com/j7cb1/PE-Appropriator/blob/main/readme/Usage.PNG)

![]( https://github.com/j7cb1/PE-Appropriator/blob/main/readme/MS-DOS%20header.PNG)
