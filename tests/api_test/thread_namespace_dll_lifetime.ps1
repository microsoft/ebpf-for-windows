# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

param(
    [Parameter(Mandatory = $true)][string]$SdkDll,
    [Parameter(Mandatory = $true)][string]$PinPath
)

$ErrorActionPreference = 'Stop'

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Threading;

public static class ThreadNamespaceLifetime
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr LoadLibraryW(string path);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool FreeLibrary(IntPtr module);
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true)]
    private static extern IntPtr GetProcAddress(IntPtr module, string name);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int NamespaceOperation(ref Guid value);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    private delegate int OpenPin([MarshalAs(UnmanagedType.LPStr)] string path);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int CloseFd(int fd);

    private static void Check(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }

    private static T Export<T>(IntPtr module, string name) where T : class
    {
        IntPtr address = GetProcAddress(module, name);
        Check(address != IntPtr.Zero, "Missing export: " + name);
        return Marshal.GetDelegateForFunctionPointer(address, typeof(T)) as T;
    }

    public static void Run(string dll, string pin)
    {
        Guid a = new Guid("2d0fcaf1-5ca8-4329-b74c-accbe7a2aa01");
        Guid b = new Guid("2d0fcaf1-5ca8-4329-b74c-accbe7a2aa02");
        IntPtr module = LoadLibraryW(dll);
        Check(module != IntPtr.Zero, "Initial LoadLibrary failed");
        NamespaceOperation set = null, get = null;
        OpenPin open = null;
        CloseFd close = null;
        Thread worker = null;
        Exception workerError = null;
        bool abort = false;
        using (var ready = new ManualResetEventSlim(false))
        using (var resume = new ManualResetEventSlim(false))
        {
            try
            {
                set = Export<NamespaceOperation>(module, "ebpf_set_thread_namespace");
                get = Export<NamespaceOperation>(module, "ebpf_get_thread_namespace");
                open = Export<OpenPin>(module, "bpf_obj_get");
                close = Export<CloseFd>(module, "ebpf_close_fd");
                Guid value = Guid.Empty;
                Check(get(ref value) == 0 && value == Guid.Empty, "Initial main selection is not default");
                Check(set(ref b) == 0, "Main SET B failed");
                worker = new Thread(() => {
                    try
                    {
                        Guid selected = b;
                        Check(get(ref selected) == 0 && selected == Guid.Empty, "Worker inherited main selection");
                        Guid desired = a;
                        Check(set(ref desired) == 0, "Worker SET A failed");
                        ready.Set();
                        resume.Wait();
                        if (abort) return;
                        selected = b;
                        Check(get(ref selected) == 0 && selected == Guid.Empty, "Reload retained worker selection");
                        Check(open(pin) < 0, "Default worker discovered A pin");
                        Check(set(ref desired) == 0, "Worker reselection failed");
                        int fd = open(pin);
                        Check(fd >= 0, "A pin did not survive reload");
                        Check(close(fd) == 0, "Closing rediscovered pin fd failed");
                    }
                    catch (Exception error) { workerError = error; ready.Set(); }
                });
                worker.Start();
                Check(ready.Wait(15000), "Worker did not become quiescent");
                if (workerError != null) throw workerError;
                Check(get(ref value) == 0 && value == b, "Worker SET changed main selection");
                Check(FreeLibrary(module), "Complete FreeLibrary failed");
                module = IntPtr.Zero;
                module = LoadLibraryW(dll);
                Check(module != IntPtr.Zero, "Reload failed");
                set = Export<NamespaceOperation>(module, "ebpf_set_thread_namespace");
                get = Export<NamespaceOperation>(module, "ebpf_get_thread_namespace");
                open = Export<OpenPin>(module, "bpf_obj_get");
                close = Export<CloseFd>(module, "ebpf_close_fd");
                value = b;
                Check(get(ref value) == 0 && value == Guid.Empty, "Reload retained main selection");
                resume.Set();
                Check(worker.Join(15000), "Reloaded worker did not finish");
                if (workerError != null) throw workerError;
                Check(get(ref value) == 0 && value == Guid.Empty, "Worker changed reloaded main selection");
            }
            finally
            {
                abort = true;
                resume.Set();
                if (worker != null && worker.IsAlive) worker.Join();
                if (module != IntPtr.Zero) Check(FreeLibrary(module), "Final FreeLibrary failed");
            }
        }
    }
}
'@

[ThreadNamespaceLifetime]::Run($SdkDll, $PinPath)
