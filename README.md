# ntfsclone2vhd

*Utility to convert ntfsclone "special images" to dynamic VHD virtual disks*

`ntfsclone` from the `ntfsprogs` package (part of `ntfs-3g`) can create an image of a NTFS disk which contains only the used clusters. The result is smaller than a full image created by `dd` or similar programs. On the downside, it cannot be directly mounted and accessed without being expanded by `ntfsclone` again first. This utility is often included on live rescue discs and can be used to make a backup of Windows systems without being able to boot Windows itself.

The VHD (Virtual Hard Disk) file format was created for Connectix Virtual PC product, and since its acquisition by Microsoft, it has been also used in Microsoft virtualization solutions. Since Windows 7, VHD images can be natively mounted for both reading and writing. A _dynamic VHD_ is a variant which stores only sectors containing data, therefore making the images smaller than full bit copies, but still allowing for growth during further use.

I have searched for a solution to convert a `.ntfsclone` image to `.vhd` and mount it in Windows, but I could not find any, so I have created this utility, `ntfsclone2vhd`. It can convert the output of `ntfsclone` into a standard VHD file, so that further data recovery can be done from the familiar Windows interface. Another possibility is to mount the image into a virtual machine, because common hypervisors understand the VHD format too.


## How to use

This is a command line utility. The built-in help provides basic usage instructions:

```
-= ntfsclone2vhd 1.1 - <jirka@fud.cz> 2017-03-20 =-
Converts ntfsclone "special image" to dynamic VHD virtual disk.

Usage:

    ntfsclone2vhd [-2] <input.ntfsclone> <output.vhd>
        - Converts input.ntfsclone to output.vhd
        - Use -2 to perform the conversion in two passes,
          necessary for metadata-only source images

    ntfsclone2vhd - <output.vhd>
        - Converts standard input to output.vhd,
          can be piped from `ntfsclone -s` directly
```

### Notes

A standard MBR sector is added at the beginning of the VHD file, so that the image can be nicely mounted by Windows. For this reason the output will be one cluster larger.

The output VHD file will be also slightly larger because `ntfsclone` works on a cluster basis, but dynamic VHD works in blocks (2 MB big by default). On real data I have observed an increase of 2.4 and 3.8%.

If the NTFS partition contains protected files (e.g. user home directories), trying to access them from another Windows installation will result in access denied errors. It is necessary to change the permissions, use low-level NTFS utilities or mount the disk e.g. in a Linux VM, where the permissions are not enforced.

Also IIRC I read somewhere that mounting a VHD with the same filesystem (by internal IDs) as already present on the same computer can create weird problems, take care. You might look at the `--new-serial` and `--new-half-serial` options of `ntfsclone` if this could be a problem.

### Metadata-only images

The `ntfsclone` tool allows creating a metadata-only image by specifying the `-m` option or `--metadata`. This sparse copy contains only the necessary clusters to be able to browse through all directories and file meta data but omits the actual file contents. The resulting files have a slightly different format and need to be processed by `ntfsclone2vhd` with an extra command line switch `-2` in order to enable the necessary two-pass conversion mode.

Piping data in through `stdin` is not possible in the two pass-mode. Also the size of the output VHD can be significantly larger than the input for these images because of how sparsely the metadata is laid out on the drive - don't be surprised by something like a 5 times increase.


## How to download binaries

Some prebuilt binaries are available on the [Releases page](https://github.com/yirkha/ntfsclone2vhd/releases). In particular for Windows, because it is not so common and easy to build programs from source on Windows.


## How to build

The project consists from just one `.c` file. I have used C for better portability. No external libraries are needed.

### Windows + MS Visual Studio 2017

1. Clone the project repository.
2. Open the supplied solution `ntfsclone2vhd.sln` in Visual Studio 2017.
3. Choose the wanted configuration ("Release", "x64" in most cases).
4. Build the project.
5. The output binary `ntfsclone2vhd.exe` is in the related `out-...` directory.

*Note:* Projects are built as "multibyte", there is no support for Unicode paths.

*Note 2:* The `.c` file might actually have to be "compiled as C++" in older versions of Visual Studio because their compiler did not support C99 syntax.

### Linux and other Unix-based systems

1. Clone the project repository.
2. Run `make` in its directory (`make DEBUG=1` if you want a debug binary).
3. The output binary `ntfsclone` is in the project's directory.

*Note:* There are hundreds of different *nix systems out there, I have tested only a few and the `Makefile` is really simple. You might need to modify a few things to get it compile. Reasonable patches are welcome.

### Other systems/platforms

You need to figure out how to compile the project yourself. It shouldn't be so hard, it's just one C file. Good luck. Again, reasonable patches are welcome.


## License

The whole project is published under the ISC license.
