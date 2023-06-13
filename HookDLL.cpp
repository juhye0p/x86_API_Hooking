#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>

#define DEF_USER32 "user32.dll"
#define DEF_MSGBOXW "MessageBoxW"

typedef int(WINAPI* PFMessageBoxW)(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType);

BYTE g_OrgByte[5] = { 0, };

BOOL Hook_Code(LPCSTR szDllName, LPCSTR szFuncName, PROC pfNew) {
    FARPROC pfOrg;
    DWORD dwOldProtect, dwAddress;
    BYTE pBuf[5] = { 0xE9, 0, }; //jmp 0x00000000
    PBYTE pByte;

    //Get The Target API Address
    pfOrg = (FARPROC)GetProcAddress(GetModuleHandleA(szDllName), szFuncName);
    pByte = (PBYTE)pfOrg;

    //Already Hooked
    if (pByte[0] == 0xE9) {
        return FALSE;
    }

    //Add WRITE Attribute To Patch 5 Byte
    VirtualProtect((LPVOID)pfOrg, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);

    //Back up Original 5 Byte
    memcpy(g_OrgByte, pfOrg, 5);

    //JMP ???? (E9 XXXX)
    //XXXX => pfNew - pfOrg - 5
    dwAddress = (DWORD)pfNew - (DWORD)pfOrg - 5;
    memcpy(&pBuf[1], &dwAddress, 4);

    //Patch 5 Byte
    memcpy(pfOrg, pBuf, 5);

    VirtualProtect((LPVOID)pfOrg, 5, dwOldProtect, &dwOldProtect);

    return TRUE;
}

BOOL UnHook_Code(LPCSTR szDllName, LPCSTR szFuncName) {
    FARPROC pFunc;
    DWORD dwOldProtect;
    PBYTE pByte;

    pFunc = GetProcAddress(GetModuleHandleA(szDllName), szFuncName);
    pByte = (PBYTE)pFunc;

    if (pByte[0] != 0xE9) {
        return FALSE;
    }

    VirtualProtect((LPVOID)pFunc, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);

    memcpy(pFunc, g_OrgByte, 5);
    VirtualProtect((LPVOID)pFunc, 5, dwOldProtect, &dwOldProtect);

    return TRUE;

}

int WINAPI NewMessageBoxW(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType) {
    FARPROC pf_msgboxw;
    int return_val;

    UnHook_Code(DEF_USER32, DEF_MSGBOXW);

    pf_msgboxw = GetProcAddress(GetModuleHandleA(DEF_USER32), DEF_MSGBOXW);
    return_val = ((PFMessageBoxW)pf_msgboxw)(hWnd, L"Hooked Message!", lpCaption, uType);

    Hook_Code(DEF_USER32, DEF_MSGBOXW, (PROC)NewMessageBoxW);
    return return_val;
}

BOOL WINAPI DllMain(HMODULE hModule,
    DWORD  fdwReason,
    LPVOID lpReserved
)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        Hook_Code(DEF_USER32, DEF_MSGBOXW, (PROC)NewMessageBoxW);
        break;
    case DLL_PROCESS_DETACH:
        UnHook_Code(DEF_USER32, DEF_MSGBOXW);
        break;
    }
    return TRUE;
}