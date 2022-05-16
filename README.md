# pcapdemo #

Small utility - programming example - about how to utilize the system's **libpcap** library.

<a name=TOP"></a>
## Table of contents

**[A. How to create autotools for this program](#A)**

**[A.1 Preparation](#A1)**

**[A.2 autoscan](#A2)**

**[A.3 automake](#A3)**

**[A.4 autoreconf](#A4)**

**[B. pcapdemo: about the pcapdemo utility](#B)**

**[B.1 What it is for?](#B1)**

**[B.2 What you will get?](#B2)**

<a name="A"></a>
## A. How to create autotools for this program

<a name="A1"></a>
## A.1 Preparation

Create a Makefile.am and the source files according to the needs, in this example all source(s) placed into the root of the working directory.

```makefile
  bin_PROGRAMS = pcapdemo
  pcapdemo_SOURCES = main.c
  pcapdemo_CFLAGS = -g -O0 -I. -I/usr/include -I/usr/local/include -Wall -Wextra
  pcapdemo_LDFLAGS = -L/usr/lib -lc -lm -lpcap -lpthread
  distdir = $(prefix)
```

[back to top](#TOP)

<a name="A2"></a>
## A.2 autoscan

Execute **autoscan** utility
```bash
autoscan -I .
```
You will have a **configure.scan** file, which will be used later as **configure.ac** after a small customization.

We going to have a new contents in that file.
```makefile
#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([FULL-PACKAGE-NAME], [VERSION], [BUG-REPORT-ADDRESS])
AC_CONFIG_SRCDIR([main.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
# FIXME: Replace `main' with a function in `-lc':
AC_CHECK_LIB([c], [main])
# FIXME: Replace `main' with a function in `-lm':
AC_CHECK_LIB([m], [main])
# FIXME: Replace `main' with a function in `-lpcap':
AC_CHECK_LIB([pcap], [main])
# FIXME: Replace `main' with a function in `-lpthread':
AC_CHECK_LIB([pthread], [main])

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for library functions.

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
```

[back to top](#TOP)

<a name="A3"></a>
## A.3 automake

We have to add **AM_INIT_AUTOMAKE** to the  ***.scan*** file at the location right after **AC_CONFIG_HEADERS([config.h])**, then copy or rename the ***configure.scan*** file to **configure.ac**.

*We can add version number, and package name, bug-report address to the package. All those are up to you though.*

Before we execute **autoreconf -ivf** - to be sure avoiding error messages - we call **automake** to generate missing parts of our new build engine.

```bash
automake -caf --foreign
```

[back to top](#TOP)

<a name="A4"></a>
## A.4 autoreconf

After executing previous command above, then we can call the next utility to generate our **configure** script.
```bash
autoreconf -ivf
```

If no error occurres, then we will have our Makefile ready to deal with our codes.

[back to top](#TOP)

<a name="B"></a>
## B. pcapdemo: about the pcapdemo utility

<a name="B1">
## B.1 What it is for?
</a>

The small utility sniffs network packages using **libpcap** and **bpf(4)** accepts two parameters at the command prompt. See usage below:
```bash
pcapdemo [-h|--help] [-i|--if <name> [filter_text]]

  where
        -h or --help - this help
        -i or --if   - device name used to pcap packets
        filter_text  - the filter applied upon pcap processing
```
You <u>*shall*</u> specify the device name to be used for capturing network packets! *(Consult your system's **ifconfig** utility manual or any kind of utility which is intended to help identify installed network cards available at hand.)*

The ***filter_text*** argument[s] is optional, using that, you can refine the pacap engine work filtering out those packtes which are not matching to the filtering criteria[s]. *Consult with your system's manuals about pcap-filters(7) and how to use them.*

**Note!** The access to the ***bpf(4)*** device - aka. Berkley Packet Filter device, can be found in your system's device subdirecory as **/dev/bpf*** - requires special privileges - most probably ***root*** access rights. If you aware of access and use *pcap* as ***root***, you can give specific group or user to have access rights to the device - consult your system's manual to share access privileges user and/or group wise. On FreeBSD you can edit ***/etc/devfs.conf*** defining which user and or group have access and how can access the device.

If you have not got the proper access rights the application will return with error.

[back to top](#TOP)

<a name="B2"></a>
## B.2 What you will get?

When you run the compiled and linked program, you will get some output - indicating that something is happening on the network your machine is connected. The code first of all will try to identify the flavour of the packages - let us be specific: frames. Dealing with the ethernet frames - depending on what type of DLT exists on the physical layer. Most probably it's going to be DLT_EN10MB, which is good for ethernets in real or virtual environments. Then the code will deal with upper layers on the ISO/OSI stack - I mean the layers above the datalink layer. When I worked with the libpcap at the first time I had to have tool which sniffs for UDP multicast transmits from a network segment which was not in the same subnet as my machine was connected. I had a spare network card which was linked directly to the switch' port on the other subnet - nowadays network guys would call that SPAN-ning - using that card and the libpcap I've got some view into the "secret" data transmits between logically linked nodes without "bother" their administrators to hack a spy-node into the system's strict configuration schemas. As I said before I was looking for udp multicast data. Therefore the next layer - or the next frame I had to deal with was the IP where you get address info (*source and destination*). This info was essential to be able to filter out those traffic which was not belonging to the multicast group address I was looking for, but still matched to UDP protocol and address type of multicast. The data streamed on different ports - having the same multicast address - depending on the role applied by the processing nodes. 

[back to top](#TOP)
