// memW.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <iostream>
#include <string>

 void GetBaseAddress(HANDLE proc_handle) {
    TCHAR proc_name[MAX_PATH];
    GetProcessImageFileName(proc_handle, proc_name, sizeof(proc_name));
    
}

uintptr_t GetModuleBaseAddress(DWORD dwProcID, char* szModuleName)
{
    uintptr_t ModuleBaseAddress = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, dwProcID);
    if (hSnapshot != INVALID_HANDLE_VALUE)
    {
        MODULEENTRY32 ModuleEntry32;
        ModuleEntry32.dwSize = sizeof(MODULEENTRY32);
        if (Module32First(hSnapshot, &ModuleEntry32))
        {
            do
            {
                if (strcmp((const char*)ModuleEntry32.szModule, szModuleName) == 0)
                {
                    ModuleBaseAddress = (uintptr_t)ModuleEntry32.modBaseAddr;
                    break;
                }
            } while (Module32Next(hSnapshot, &ModuleEntry32));
        }
        CloseHandle(hSnapshot);
    }
    return ModuleBaseAddress;
}

HMODULE GetModule(HANDLE pHandle, std::wstring wsName) {
    
    HMODULE hMods[1024];
    unsigned int i;
    DWORD cbNeeded;

    if (EnumProcessModules(pHandle, hMods, sizeof(hMods), &cbNeeded)) {
        for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            TCHAR szModName[MAX_PATH];
            if (GetModuleFileNameEx(pHandle, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR))) {
                std::wstring wsModName = szModName;
                if (wsModName.find(wsName) != std::string::npos) {
                    return hMods[i];
                }
            }
        }
    }
    return nullptr;
}

int main()
{
    std::cout << "Hello World!\n";

    DWORD pid;

    // Get window
    HWND hWnd = FindWindow(nullptr, L"Untitled - Notepad");

    // Get the PID
    GetWindowThreadProcessId(hWnd, &pid);

    // Get the process handle
    HANDLE pHandle = OpenProcess(PROCESS_VM_READ, FALSE, pid);

    // Get base module name
    TCHAR pName[MAX_PATH];
    GetProcessImageFileName(pHandle, pName, sizeof(pName));

    // Get base module address
    HMODULE hMod = GetModule(pHandle, pName);
    DWORD PROCESS_BASE_ADDR = (DWORD)hMod;

    // Read from memory
    uintptr_t baseObj;
    ReadProcessMemory(pHandle, (LPVOID)PROCESS_BASE_ADDR, &baseObj, sizeof(baseObj), NULL);

    printf("Memory from base address reads: %zd\n", baseObj);
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
