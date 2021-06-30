PowerShell Script to help find remnants of Scheduled Tasks which only exist in the registry.

Run the script as follows:
1. Open an administrative CMD or PowerShell
2. Change Directories to where you saved the script
3. Run with command:
**powershell.exe -ExecutionPolicy Bypass -File .\findRegistryTaskCache.ps1**

If any potentially dangerous Scheduled Tasks are found in the registry, they will be logged.  The tool will also check if the found Scheduled Tasks exist in C:\Windows\System32\Tasks.  And commands which can be used to remove the found potentially dangerous tasks will be listed at the bottom of the output.

A log is always created after each run of the tool and is saved into the same directory the tool was run from.
