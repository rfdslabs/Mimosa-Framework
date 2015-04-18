Copyright (c) 2007-2012 by Errata Security

FERRET - a network analysis tool


ABSTRACT

This tool extracts interesting bits from network traffic. One use is
to feed the "hamster" tool. Another use is to dump the output into
a text file, then use indexers and grep programs to analyze it.

BUILDING

On Linux, just type "make". There is no configure.

On Windows, either use MingGW or the VisualStudio 2010 project file.

For everything else, just compile all the source files together. There
aren't any special build options.

32BIT AND 64BIT

The older version had some 64-bit errors. They should all be fixed in
the current version.

LIBPCAP

The program will attempt to load the "libpcap" library if its exists,
but will otherwise run without it. You don't need libpcap for offline
processing of capture files, nor do you really need it for Linux (where
AF_PACKET is used instead).

If you need libpcap, and dynamic linking doesn't work, you can link 
it statically by defining "STATICPCAP" and recompiling.

On Windows, you must have "winpcap" installed.


IPv6

IPv6 is supported, but not all the encapsulation methods (like IPv6 on
IPv4).


VULNERABILITIES IN THE CODE

This code is just hacked up as a prototype. The code was rush out for 
BlackHat Federal (March 1, 2007). There are likely vulnerabilities.

I haven't spent any time maintainin the code.

USAGE

To get help, run it with no arguments:
    ferret

To analyze a file, provide it with the '-f' argument:
    ferret -f myfile.pcap

To analyze a lot of files, use wildcards and pathnames as appropriate:
    ferret -f mydir\*.pcap

To analyze a live network, use the '-i' option:
    ferret -i

To analyze a specific adapter, specify its name:
    ferret -i eth0

To analyze a specific adapter, you may also use its index number:
    ferret -i 1

To get a list of adapters, use the '-W' option:
    ferret -W


DIRECTORY STRUCTURE

Ferret/bin/         This is where the program goes when it's built (*.exe)
Ferret/tmp/         Temporary files, like object files (*.o, *.obj)
Ferret/build/		Makefiles and project workspaces (*.dsw, *.dsp)
Ferret/misc/		Miscellaneous files
Ferret/src/			Source files (*.c, *.h)


AUTHOR:

Robert Graham <robert_david_graham@yahoo.com>

