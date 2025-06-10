This is a repo for extracting unmanaged DLLs and converting them to source code.

I built this because I had a client with this specific need.


The Java script should be used in Ghidra to export DLL code as a single script

Open up your DLL in Ghidra, do analysis with defaults. 

Go to Window -> Script Manager and add the ExportDecompiled.java 

Run the script, give an export file name.

Take that script and put it in the folder "input"
