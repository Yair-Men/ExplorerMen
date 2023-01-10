using System;
using static Windows.API;
using static Windows.Enums;
using static ExplorerMen.Utils;
using static ExplorerMen.Utils.ColorStatus;

namespace ExplorerMen
{
    internal class Service
    {
        string serviceName;
        string driverPath;
        IntPtr hSCM = IntPtr.Zero;
        IntPtr hService = IntPtr.Zero;

        public string DriverPath { set => driverPath = value; }

        public Service(string serviceName)
        {
            hSCM = OpenSCManagerA(".", null, SC_MANAGER_CREATE_SERVICE);
            if (hSCM == IntPtr.Zero)
            {
                PrettyPrint(string.Format("[-] Failed to get handle to SCM. (Error Code: {0})", GetLastError), Error);
                Environment.Exit(1);
            }

            if (serviceName == null)
                this.serviceName = "PROCEXP152";
            else
                this.serviceName = serviceName.Length == 0 ? "PROCEXP152" : serviceName;

            hService = OpenServiceA(hSCM, this.serviceName, SERVICE_START | SERVICE_CHANGE_CONFIG);
        }

        public bool CreateService()
        {
            if (hService != IntPtr.Zero)
            {
                PrettyPrint(string.Format("[!] Service \"{0}\" allready exists", serviceName), Info);
                return StartService();
            }

            hService = CreateServiceA(hSCM, serviceName, serviceName, SC_MANAGER_CREATE_SERVICE | SERVICE_START | SERVICE_CHANGE_CONFIG,
                SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, driverPath);

            int errCode = GetLastError;

            if (hService == IntPtr.Zero)
            {
                PrettyPrint(string.Format("[-] Failed To Create Service \"{0}\". (Error Code: {1})", serviceName, GetLastError), Error);
            }
            else if (errCode == 1073) // ERROR_SERVICE_EXISTS
            {
                PrettyPrint(string.Format("[!] Service \"{0}\" allready exists", serviceName), Info);
                return StartService();
            }
            else if (errCode == 0)
            {
                PrettyPrint(string.Format("[+] Service \"{0}\" Created Successfully", serviceName), Success);
                return StartService();
            }
            else if (errCode != 0)
            {
                PrettyPrint(string.Format("[!] Hit last else if in create service. (Error Code: {0})\n", errCode), Info);
            }

            return false;
        }

        public bool StartService()
        {
            if (hService == IntPtr.Zero && GetLastError == 1060) // 1060 == ERROR_SERVICE_DOES_NOT_EXIST
            {
                PrettyPrint($"[-] Service \"{serviceName}\" doesn't exists", Error);
                return false;
            }
            bool OK = StartServiceA(hService, 0, null);

            if (!OK)
            {
                int errCode = GetLastError;

                // 183 == ERROR_ALLREADY_EXISTS, 1056 = ERROR_SERVICE_ALREADY_RUNNING
                if (errCode == 183 || errCode == 1056)
                {
                    PrettyPrint(string.Format("[!] Service \"{0}\" allready running", serviceName), Info);
                    return true;
                }
                else if (errCode == 1058) // 1058 == ERROR_SERVICE_DISABLED
                {
                    PrettyPrint(string.Format("[!] Service \"{0}\" is in disabled state", serviceName), Info);
                    if (EnableService()) return true;
                }
                else
                {
                    PrettyPrint(string.Format("[-] Failed to start Service \"{0}\". (Error Code: {1})", serviceName, errCode), Error);
                    return false;
                }
            }
            PrettyPrint("[+] Service started successfully", Success);

            return true;
        }

        // We only get here when the service marked for deletion, Windows disables the service
        private bool EnableService()
        {
            bool OK = ChangeServiceConfigA(hService, SERVICE_NO_CHANGE, SERVICE_DEMAND_START, SERVICE_NO_CHANGE);

            // When errCode == 1072 (ERROR_SERVICE_MARKED_FOR_DELETE) it will be start anyway, but we will need this hack everytime unless a new service will be created
            if (!OK && GetLastError != 1072)
            {
                PrettyPrint(string.Format("[-] Failed to change service \"{0}\" config. (Error Code: {1})", serviceName, GetLastError), Error);
                PrettyPrint("[!] Try to install the service again with different name or use sc.exe to start the service", Info);
                return false;
            }
            PrettyPrint(string.Format("[+] Service \"{0}\" enabled once again", serviceName), Success);
            return true;
        }


        ~Service()
        {
            if (hService != IntPtr.Zero) CloseServiceHandle(hService);
            if (hSCM != IntPtr.Zero) CloseServiceHandle(hSCM);
        }

    }
}
