/* Written by Havox */

#include <Windows.h>
#include <Psapi.h>
#include <iostream>
#include <tchar.h>
#include <fstream>
#include "HeaderAnalysis.h"
#include <TlHelp32.h>  // for CreateToolhelp32Snapshot
#pragma comment(lib, "Psapi.lib")

void enumChildProcess(DWORD processID, std::wofstream& outputFile, std::wofstream& outputFile1) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        std::cerr << "Error: CreateToolhelp32Snapshot failed" << std::endl;
        return;
    }
    PROCESSENTRY32 ProcessEntry;
    ProcessEntry.dwSize = sizeof(PROCESSENTRY32);

    bool hasChildren = false;
    if (Process32First(hSnap, &ProcessEntry)) {
        do {
            if (ProcessEntry.th32ParentProcessID == processID) {
                outputFile << "          \"Child Process PID\": " << ProcessEntry.th32ProcessID << ",\n";
                //PrintImportsAPI(ProcessEntry.th32ProcessID,outputFile1);
                hasChildren = true;
            }
        } while (Process32Next(hSnap, &ProcessEntry));
    }
    if (!hasChildren) {
        outputFile << "          \"Child Process PID\": \"None\",\n";
    }
    CloseHandle(hSnap);
}

void EnumProcessId() {

    std::wofstream outputFile("Process_information.json", std::ios::app);

    std::wofstream outputFile1("Modules_Imported.json", std::ios::app);

    if (!outputFile) {
        std::cerr << "Error: Unable to create output file." << std::endl;
        return;
    }
    if (!outputFile1) {
        std::cerr << "Error: Unable to create output file." << std::endl;
        return;
    }


    DWORD aProcess[1024];
    DWORD cbNeeded;
    DWORD cProcess;

    if (!EnumProcesses(aProcess, sizeof(aProcess), &cbNeeded)) {
        std::cerr << "Error: EnumProcesses failed." << std::endl;
        return;
    }

    cProcess = cbNeeded / sizeof(DWORD);
    outputFile << "{\n  \"Number of Processes\": " << cProcess << ",\n  \"Processes\": [\n";

    bool firstProcess = true;
    for (unsigned int i = 0; i < cProcess; i++) {
        if (aProcess[i] != 0) {
            if (!firstProcess) outputFile << "    },\n";
            firstProcess = false;

            outputFile << "    {\n      \"PID\": " << aProcess[i] << ",\n";
            PrintImportsAPI(aProcess[i],outputFile1);

            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, aProcess[i]);
            if (hProcess) {
                TCHAR sProcessName[MAX_PATH] = TEXT("Unknown");
                HMODULE hMod;
                DWORD cbNeededName;

                if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeededName)) {
                    GetModuleBaseName(hProcess, hMod, sProcessName, MAX_PATH);
                }
                outputFile << "      \"Name\": \"" << sProcessName << "\",\n";

                HMODULE hMods[1024];
                DWORD cbModulesNeeded;
                if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbModulesNeeded)) {
                    DWORD numModules = cbModulesNeeded / sizeof(HMODULE);
                    outputFile << "       \"Modules Loaded by Process\": [\n";

                    for (DWORD j = 0; j < numModules; j++) {
                        TCHAR moduleName[MAX_PATH];
                        if (GetModuleFileNameEx(hProcess, hMods[j], moduleName, MAX_PATH)) {
                            outputFile << "        \"" << moduleName << "\"";
                            if (j < numModules - 1) outputFile << ",";
                            outputFile << "\n";
                        }
                    }
                    outputFile << "       ]\n";
                }
                else {
                    outputFile << "      \"Modules Loaded by Process\": \"Error: Could not fetch modules.\",\n";
                }

                enumChildProcess(aProcess[i], outputFile,outputFile1);
                CloseHandle(hProcess);
            }
            else {
                outputFile << "      \"Name\": \"Access Denied - Check you Dump Brain :/ \"\n";
            }
        }
    }
    outputFile << "    }\n  ]\n}";
    outputFile.close();
}

int main() {
    while (true) EnumProcessId();
    return 0;
}
