DMA-ProcessDump:
===============================
DMA-ProcessDump is a tool that allows you to dump processes running inside a QEMU virtual machine (running a windows operating system) from a linux host using MemProcFS

Prerequisites:
===========
- A QEMU virtual machine running windows
- Huge Pages configured on your linux installation
- Edit your QEMU XML to use the HugePages memory backend and set a path for the QMP socket as instructed here (https://github.com/ufrisk/LeechCore/wiki/Device_QEMU)

Installing:
===========
Run make from the root folder, it will build all dependencies and then build the main tool. Make sure you have all dependencies for MemProcFS installed.

Usage:
===========
Run the ExecutableDumper with root permissions and provide it the name of the process and the memory map acquisition socket path from your QEMU XML file.  

**Example**: sudo ./ExecutableDumper -p explorer.exe -s /tmp/qmp-win10.sock
