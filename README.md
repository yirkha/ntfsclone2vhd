# ntfsclone2vhd

*Utility to convert ntfsclone "special images" to dynamic VHD virtual disks*

`ntfsclone` from the `ntfsprogs` package (part of `ntfs-3g`) can create an image of a NTFS disk which contains only the used clusters. The result is smaller than a full image created by `dd` or similar programs. On the downside, it cannot be directly mounted and accessed without being expanded by `ntfsclone` again first. This utility is often included on live rescue discs and can be used to make a backup of Windows systems without being able to boot Windows itself.

The VHD (Virtual Hard Disk) file format was created for Connectix Virtual PC product, and since its acquisition by Microsoft, it has been also used in Microsoft virtualization solutions. Since Windows 7, VHD images can be natively mounted for both reading and writing. A _dynamic VHD_ is a variant which stores only sectors containing data, therefore making the images smaller than full bit copies, but still allowing for growth during further use.

I have searched for a solution to convert a `.ntfsclone` image to `.vhd` and mount it in Windows, but I could not find any, so I have created this utility, `ntfsclone2vhd`. It can convert the output of `ntfsclone` into a standard VHD file, so that further data recovery can be done from the familiar Windows interface. Another possibility is to mount the image into a virtual machine, because common hypervisors understand the VHD format too.


## How to use

This is a command line utility.

```
-= ntfsclone2vhd 1.0 - <jirka@fud.cz> 2015-03-10 =-
Converts ntfsclone "special image" to dynamic VHD virtual disk.

Usage:

    ntfsclone2vhd <input.ntfsclone> <output.vhd>
        - Converts input.ntfsclone to output.vhd

    ntfsclone2vhd - <output.vhd>
        - Converts standard input to output.vhd,
          can be piped from `ntfsclone -s` directly
```

A standard MBR sector is added at the beginning of the VHD file, so that the image can be nicely mounted by Windows. For this reason the output will be one cluster larger.

The output VHD file will be also slightly larger because `ntfsclone` works on a cluster basis, but dynamic VHD works in blocks (2 MB big by default). On real data I have observed an increase of 2.4 and 3.8%.

If the NTFS partition contains protected files (e.g. user home directories), trying to access them from another Windows installation will result in access denied errors. It is necessary to change the permissions, use low-level NTFS utilities or mount the disk e.g. in a Linux VM, where the permissions are not enforced.

Also IIRC I read somewhere that mounting a VHD with the same filesystem (by internal IDs) as already present on the same computer can create weird problems, take care.


## How to build

The project consists from just one `.c` file. I have used C for better portability, no external libraries needed.

### Windows + MS Visual Studio 2013

1. Clone the project.
1. Open the suplied solution `ntfsclone2vhd.sln` in Visual Studio.
2. Build the project 

*Note:* Projects are built as "multibyte", there is no support for Unicode paths.

*Note 2:* The `.c` file is actually compiled as C++ because Visual Studio compiler does not support C99 syntax.

### Linux and other Unix-based systems

1. Clone the project.
2. Run `make`.

*Note:* There are hundreds of different *nix systems out there, I have tested only a few and the `Makefile` is really simple. You might need to modify a few things to get it compile. Sane patches are welcome.

### Other systems/platforms

You need to figure how to compile the project yourself, shouldn't be so hard, it's just one C file. Good luck. Again, sane patches are welcome.


## Built binaries

Because it is not so common and easy to build stuff from source on Windows, pre-built binaries for Windows are available on the [Releases page](https://github.com/yirkha/ntfsclone2vhd/releases).


## License

The whole project is published under the ISC license.
