// Writtten an tested by havox
// re
// code to analysis the malware using the stack menthods and dynamically using PE header analysis and Some string matching with YARA Rules

#include <iostream>
#include <Windows.h>
#include <Psapi.h>
#include <tchar.h>
#include <AclAPI.h>
#include <fstream>
#include <TlHelp32.h>
#include <string>
#include "HeaderAnalysis.h"
#pragma comment(lib, "Psapi.lib")

#define SECURITY_MANDATORY_UNTRUSTED_RID            (0x00000000L)
#define SECURITY_MANDATORY_LOW_RID                  (0x00001000L)
#define SECURITY_MANDATORY_MEDIUM_RID               (0x00002000L)
#define SECURITY_MANDATORY_HIGH_RID                 (0x00003000L)
#define SECURITY_MANDATORY_SYSTEM_RID               (0x00004000L)
#define SECURITY_MANDATORY_PROTECTED_PROCESS_RID    (0x00005000L)


void checkProcessIntegrety(HANDLE hProcess) {
    HANDLE hToken;
    DWORD dwSizwe;
    PTOKEN_MANDATORY_LABEL pTIL;

    if (!OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_QUERY_SOURCE, &hToken)) {
        std::cout << "OpenProcess Failed" << std::endl;
        return;
    }
    GetTokenInformation(hToken, TokenIntegrityLevel, &pTIL, 0, &dwSizwe);
    pTIL = (PTOKEN_MANDATORY_LABEL)LocalAlloc(0, dwSizwe);

    if (!GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, dwSizwe, &dwSizwe)) {
        DWORD dwError = GetLastError();
        std::cout << "GetTokenInformation failed. Error: " << dwError << std::endl;
        CloseHandle(hToken);
        return;
    }

    DWORD dwIntere = *GetSidSubAuthority(pTIL->Label.Sid, *GetSidSubAuthorityCount(pTIL->Label.Sid) - 1);

    if (dwIntere == SECURITY_MANDATORY_UNTRUSTED_RID) {
        std::cout << "Untrusted integrity level" << std::endl;
    }
    else if (dwIntere == SECURITY_MANDATORY_LOW_RID) {
        std::cout << "Low integrity level" << std::endl;
    }
    else if (dwIntere == SECURITY_MANDATORY_MEDIUM_RID) {
        std::cout << "Medium integrity level" << std::endl;
    }
    else if (dwIntere == SECURITY_MANDATORY_HIGH_RID) {
        std::cout << "High integrity level" << std::endl;
    }
    else if (dwIntere == SECURITY_MANDATORY_SYSTEM_RID) {
        std::cout << "System integrity level" << std::endl;
    }
    else if (dwIntere == SECURITY_MANDATORY_PROTECTED_PROCESS_RID) {
        std::cout << "Protected Process integrity level" << std::endl;
    }
    else {
        std::cout << "Unknown integrity level" << std::endl;
    }

    LocalFree(pTIL);
    CloseHandle(hToken);
}

// Enable SeDebugPrivilege for accessing all processes
BOOL EnableDebugPrivilege() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        std::cout << "[!] Failed to open process token => " << GetLastError() << std::endl;
        return FALSE;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid)) {
        std::cout << "[!] Failed to lookup privilege => " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return FALSE;
    }

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        std::cout << "[!] Failed to adjust privilege => " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return FALSE;
    }

    CloseHandle(hToken);
    return TRUE;
}

// Analyze imports for a single module in the process's memory

/* ACTUAL FLOW how PE Header works look before analysing this code
                DOS_HEADER -> e_lfanew -> NT_HEADERS
                                            ├── FILE_HEADER
                                            ├── OPTIONAL_HEADER -> ImageBase
                                            ├── DataDirectory[IMPORT] -> importRVA
                                                    ├── importDesc (Import Table)
                                                    │      ├── DLL Names
                                                    │      ├── Function Names (Thunk Table)

              */

void AnalyzeModuleImports(HANDLE hProcess, HMODULE hModule, const TCHAR* moduleName, std::wofstream& outfile) {

    std::wcout << L"\n[*] Module: " << moduleName << std::endl;
    outfile << L"\n[+] Module: " << moduleName << std::endl;

    // Dynamically allocate buffers to avoid stack overflow
    BYTE* dosBuffer = new BYTE[sizeof(IMAGE_DOS_HEADER)];
    SIZE_T bytesRead;

    // Read DOS header
    if (!ReadProcessMemory(hProcess, hModule, dosBuffer, sizeof(IMAGE_DOS_HEADER), &bytesRead)) {
        std::cout << "[!] Failed to read DOS header => " << GetLastError() << std::endl;
        outfile << "[!] Failed to read DOS header => " << GetLastError() << std::endl;
        delete[] dosBuffer;
        return;
    }

    // Let's start to parse the PE file to enum the Actual API's :) -> interesting part

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dosBuffer;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        std::cout << "[!] Invalid DOS signature" << std::endl;
        outfile << "[!] Invalid DOS signature" << std::endl;
        delete[] dosBuffer;
        return;
    }

    // Read NT header
    BYTE* ntBuffer = new BYTE[sizeof(IMAGE_NT_HEADERS)];
    if (!ReadProcessMemory(hProcess, (BYTE*)hModule + dosHeader->e_lfanew, ntBuffer, sizeof(IMAGE_NT_HEADERS), &bytesRead)) {
        std::cout << "[!] Failed to read NT header => " << GetLastError() << std::endl;
        delete[] dosBuffer;
        delete[] ntBuffer;
        return;
    }

    // using NT_Headers to get the optional header to get the ImageBase as entry point to access the import table & address table
            // for that we accessing via DOS_Header's e_lfanew contains the offset to NT_HEADER by adding the offset to the base of the file....
            // ...lpbase to get the actual address of NT_HEADER

    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)ntBuffer;
    if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
        std::cout << "[!] Invalid NT signature" << std::endl;
        delete[] dosBuffer;
        delete[] ntBuffer;
        return;
    }

    // Next ! Here the important part of this code that, to enum the Import from the NT_HEADER->OPTIONAL_HEADER we using..... 
            // ....IMAGE_DIRECTORY_ENTRY_IMPORT, for that we retrive the RVA (Relative address table) from the data directory in the optional header
            // ....here we simply getting the RVA address not the actual address 
            // 

    DWORD importRVA = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (importRVA == 0) {
        std::cout << "[!] No Imports Found" << std::endl;
        outfile << "[!] No Imports Found" << std::endl;
        delete[] dosBuffer;
        delete[] ntBuffer;
        return;
    }

    // Read import directory
    BYTE* importBuffer = new BYTE[4096]; // Adjust size as needed
    if (!ReadProcessMemory(hProcess, (BYTE*)hModule + importRVA, importBuffer, 4096, &bytesRead)) {
        std::cout << "[!] Failed to read import table => " << GetLastError() << std::endl;
        delete[] dosBuffer;
        delete[] ntBuffer;
        delete[] importBuffer;
        return;
    }

    // Now we have to export the modules but we actually need the actual address, Don't we have the importRVA addredd so add....
            // .....that to get the actual memory pointer 
            // 
            // get to understand see the flow on top 


    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)importBuffer;
    while (importDesc->Name != 0) {
        // Read DLL name
        char* dllName = new char[256];
        if (!ReadProcessMemory(hProcess, (BYTE*)hModule + importDesc->Name, dllName, 256, &bytesRead)) {
            std::cout << "[!] Failed to read DLL name => " << GetLastError() << std::endl;
            delete[] dllName;
            break;
        }
        dllName[bytesRead < 256 ? bytesRead : 255] = '\0'; // Ensure null termination
        std::cout << "    DLL: " << dllName << std::endl;
        outfile << "    DLL: " << dllName << std::endl;

        // Read thunk data
        BYTE* thunkBuffer = new BYTE[4096];
        DWORD thunkRVA = importDesc->OriginalFirstThunk ? importDesc->OriginalFirstThunk : importDesc->FirstThunk;
        if (!ReadProcessMemory(hProcess, (BYTE*)hModule + thunkRVA, thunkBuffer, 4096, &bytesRead)) {
            std::cout << "[!] Failed to read thunk data => " << GetLastError() << std::endl;
            delete[] dllName;
            delete[] thunkBuffer;
            break;
        }

        PIMAGE_THUNK_DATA thunkData = (PIMAGE_THUNK_DATA)thunkBuffer;
        int j = 0;
        while (thunkData[j].u1.AddressOfData != 0) {
            if (thunkData[j].u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                std::cout << "        API: Ordinal " << (thunkData[j].u1.Ordinal & 0xFFFF) << std::endl;
            }
            else {
                BYTE* nameBuffer = new BYTE[256];
                if (!ReadProcessMemory(hProcess, (BYTE*)hModule + thunkData[j].u1.AddressOfData, nameBuffer, 256, &bytesRead)) {
                    std::cout << "[!] Failed to read import name => " << GetLastError() << std::endl;
                    delete[] nameBuffer;
                    break;
                }
                PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)nameBuffer;

                std::cout << "        API: " << importByName->Name << std::endl;
                outfile << "        API: " << importByName->Name << std::endl;
                delete[] nameBuffer;
            }
            j++;
        }
        delete[] dllName;
        delete[] thunkBuffer;
        importDesc++;
    }

    // Clean up
    delete[] dosBuffer;
    delete[] ntBuffer;
    delete[] importBuffer;
}
//malware_learn
// Enumerate imports for all modules in a process
void PrintImportsAPI(DWORD processID, std::wofstream& outFile) {


    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
    checkProcessIntegrety(hProcess);

    if (hProcess == nullptr) {
        std::cout << "[!] Failed to open process " << processID << " => " << GetLastError() << std::endl;
        return;
    }

    HMODULE hMods[1024];
    DWORD cbNeeded;

    if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        std::cout << "[!] Failed to enumerate modules for PID " << processID << " => " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return;
    }

    DWORD modCount = cbNeeded / sizeof(HMODULE);
    for (DWORD i = 0; i < modCount; i++) {
        TCHAR szModName[MAX_PATH];
        if (GetModuleFileNameEx(hProcess, hMods[i], szModName, MAX_PATH)) {
            AnalyzeModuleImports(hProcess, hMods[i], szModName, outFile);
        }
    }
    CloseHandle(hProcess);
}


// For testing purpose 

//int main() {
//    // Elevate privileges
//    if (!EnableDebugPrivilege()) {
//        std::cout << "[!] Warning: Could not enable SeDebugPrivilege. Some processes may be inaccessible." << std::endl;
//    }
//
//    DWORD pid;
//    std::cout << "Enter the Process ID: ";
//    std::cin >> pid;
//    std::wofstream outfile("Module_imports.json" , std::ios::app);
//    PrintImportsAPI(pid,outfile);
//
//    return 0;
//}
