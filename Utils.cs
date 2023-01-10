using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using static Windows.API;
using static Windows.Enums;
using static Windows.Structs;

namespace ExplorerMen
{
    class Utils
    {
        public static bool Is64Bit { get => Marshal.SizeOf(typeof(IntPtr)) == 8; }
        public static string AppName { get => AppDomain.CurrentDomain.FriendlyName; }

        // Print with colors
        public enum ColorStatus
        {
            Success = ConsoleColor.DarkGreen,
            Error = ConsoleColor.Red,
            Info = ConsoleColor.Yellow
        }

        public static void PrettyPrint(string str, ColorStatus status)
        {
            Console.ForegroundColor = (ConsoleColor)status;
            Console.WriteLine(str);
            Console.ResetColor();
        }

        // Simple Usage and full help with all args
        public static string Usage
        {
            get
            {
                return "==== Usage ====\n" +
                    $"{AppName} {{ /install:<DRIVER_FILE_FULL_PATH> || /service:<SERVICE_NAME> }} {{ /pid:<PID> || /name:<PROCESS_NAME> }} [/watchdog]";
            }
        }

        public static string Help
        {
            get
            {
                return "==== Help Menu ====\n" +
                    "/install: - Full Path to the Driver file to be install.\n" +
                    "/service: -\n" +
                    "    With /install - Arbitrary name for the new service\n" +
                    "    Without /install - An existing service name (Will start the service if needed)\n" +
                    "/pid: - Target Process Id\n" +
                    "/name: - Target Process Name (Case In-sensitive)\n" +
                    "/watchdog - Monitor the service, if it comes up again - kill it";
            }
        }

        public static string Examples
        {
            get
            {
                return "==== Example ====\n" +
                    "[!] Load driver at C:\\driver.sys as service with the name nonsense and kill process with id 123\n" +
                    $"{AppName} /install:C:\\driver.sys /service:nonsense /pid 123\n\n" +

                    "[!] Start the service nonsense and kill process with name MsMpEng.exe\n" +
                    $"{AppName} /service:nonsense /name:MsMpEng\n\n" +

                    "[!] Start the service nonsense and kill process with id 123. Keep monitor the process, kill it everytime it is up again\n" +
                    $"{AppName} /service:nonsense /pid:123 /watchdog";
            }
        }

        /// <summary>
        ///  Gets a PID and enumerate all handles in the system using NtQuerySystemInformation
        /// </summary>
        /// <param name="PID"></param>
        /// <returns> returns a list of SYSTEM_HANDLE_TABLE_ENTRY_INFO only for entries where the UniqueProcesId is the same as the PID </returns>
        public static List<SYSTEM_HANDLE_TABLE_ENTRY_INFO> GetHandles(int PID)
        {
            int HandleInfoSize = 0x10000;
            int RetLen = 0;
            IntPtr pInfo = Marshal.AllocHGlobal(HandleInfoSize);

            long NumberOfHandles = 0;
            List<SYSTEM_HANDLE_TABLE_ENTRY_INFO> lstHandlesTable = new();
            int TableEntrySize = Marshal.SizeOf(typeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO));


            while (NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS.SystemHandleInformation, pInfo, HandleInfoSize, ref RetLen) == NTSTATUS.InfoLengthMismatch)
            {
                HandleInfoSize = RetLen;
                Marshal.FreeHGlobal(pInfo);
                pInfo = Marshal.AllocHGlobal(RetLen);
            }


            if (Is64Bit)
            {
                NumberOfHandles = Marshal.ReadInt64(pInfo);
                pInfo += 8;
            }
            else
            {
                NumberOfHandles = Marshal.ReadInt32(pInfo);
                pInfo += 4;
            }



            for (long i = 0; i < NumberOfHandles; i++)
            {
                SYSTEM_HANDLE_TABLE_ENTRY_INFO HandleEntry = (SYSTEM_HANDLE_TABLE_ENTRY_INFO)Marshal.PtrToStructure(pInfo, typeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO));

                pInfo += TableEntrySize;

                if (HandleEntry.UniqueProcessId == PID)
                    lstHandlesTable.Add(HandleEntry);
            }
            return lstHandlesTable;
        }




        /// <summary>
        /// Using NtQueryObject WinAPI to determine the type of the given object
        /// </summary>
        /// <param name="hObject"> Handle to an object </param>
        /// <returns> A String contains the object/handle type or null </returns>
        public static string GetHandleType(IntPtr hObject)
        {
            string results = null;
            int archBit = Is64Bit ? 8 : 4;
            uint infoLength = (uint)Marshal.SizeOf(typeof(PUBLIC_OBJECT_TYPE_INFORMATION)) * (uint)archBit;
            NTSTATUS ntStat = 0;
            IntPtr pInfo = Marshal.AllocHGlobal((int)infoLength);

            ntStat = NtQueryObject(hObject, OBJECT_INFORMATION_CLASS.ObjectTypeInformation, pInfo, infoLength, ref infoLength);

            if (ntStat == NTSTATUS.InvalidHandle || ntStat != NTSTATUS.Success)
            {
#if DEBUG
                Console.WriteLine("[!] Non zero NTSTAUTS in NtQueryObject: {0}", ntStat);
#endif
                return null;
            }

            try
            {
                UNICODE_STRING uniStr = (UNICODE_STRING)Marshal.PtrToStructure(pInfo, typeof(UNICODE_STRING));
                results = uniStr.Length == 0 ? null : uniStr.Buffer;
            }
            catch (Exception)
            {
#if DEBUG
                Console.WriteLine("[-] NtQueryObject Exception");
#endif
            }
            finally
            {
                Marshal.FreeHGlobal(pInfo);
            }

            return results;
        }
    }
}