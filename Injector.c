#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>

#define DesiredAccess (PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD)

void error(LPCSTR FunctionName)
{
    printf("[-] %s Failed\n", FunctionName);
    printf("[-] GetLastError : %d\n", GetLastError());
}

DWORD GetPID() {
    HANDLE hProcess = NULL;
    PROCESSENTRY32 pe32 = { 0 };
    hProcess = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hProcess, &pe32)) {
        do {
            if (!wcscmp(pe32.szExeFile, TEXT("MSGBOX.exe"))) {
                return pe32.th32ProcessID;
            }
        } while (Process32Next(hProcess, &pe32));
    }
    return 0xFFFFFFFF;

}

int main(int argc, char* argv[])
{
    DWORD PID = 0xFFFFFFFF;

    while (TRUE) {
        PID = GetPID();
        if (PID != 0xFFFFFFFF) {
            break;
        }
        else {
            printf("[-] NOT FOUND PROCESS..\n");
            Sleep(1000);
        }
    }

    char* p = "[PATH]\\HookDLL.dll"; //Change
    LPCSTR Path = p;
    size_t length = strlen(Path);

    system("cls");
    printf("[+] PROCESS FOUND!\n\n");

    printf("[*] Attempting To Get The Target Process' Permissions...\n\n");

    HANDLE hProcess = OpenProcess(DesiredAccess, FALSE, PID);

    if (hProcess == NULL)
    {
        error("OpenProcess");
        return -1;
    }

    printf("[*] OpenProcess Complete!\n");
    printf("[+] Process Handle : 0x%X\n\n", hProcess);

    PVOID PathAddress = VirtualAllocEx(hProcess, NULL, length, MEM_COMMIT, PAGE_READWRITE);

    if (PathAddress == NULL)
    {
        error("VirtualAllocEx");
        return -1;
    }

    printf("[*] Allocating Buffer To The Target Process Complete!\n");
    printf("[+] Buffer Address : 0x%p\n\n", PathAddress);

    printf("[*] Writing DLL Path...\n");

    if (WriteProcessMemory(hProcess, PathAddress, Path, length, NULL) == FALSE)
    {
        error("WriteProcessMemory");
        return -1;
    }

    printf("[*] Writing DLL Path Complete!\n\n");

    printf("[*] Finding Kernel32.dll...\n");

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");

    if (hKernel32 == NULL)
    {
        error("GetModuleHandleA");
        return -1;
    }

    printf("[*] Kernel32.dll Found!\n");
    printf("[+] Kernel32.dll : 0x%p\n\n", hKernel32);

    printf("[*] Finding LoadLibraryA()...\n");

    FARPROC lpLoadLibraryA = GetProcAddress(hKernel32, "LoadLibraryA");

    if (lpLoadLibraryA == NULL)
    {
        error("GetProcAddress");
        return -1;
    }

    printf("[*] LoadLibraryA() Found!\n");
    printf("[+] LoadLibraryA() : 0x%p\n\n", lpLoadLibraryA);

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, NULL, lpLoadLibraryA, PathAddress, 0, NULL);

    if (hThread == NULL)
    {
        error("CreateRemoteThread");
        return -1;
    }

    WaitForSingleObject(hThread, INFINITE);

    printf("[+] DLL Injection Complete!!\n\n");

    return 0;
}