/*Written by Havox*/

#include <Windows.h>
#include <Psapi.h>
#include <iostream>
#include <tchar.h>
#include <fstream>
#include <TlHelp32.h>  // for createToolhelp32snapshot

void enumchildprocess(DWORD processID, std::wofstream& outputfile) {  // to enumerate the child process 
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        std::cerr << "Error: CreateToolhelp32snapshot not found" << std::endl;
        return;
    }
    PROCESSENTRY32 ProcessEntry;
    ProcessEntry.dwSize = sizeof(PROCESSENTRY32);

    bool haschildren = false;
    if (Process32First(hSnap, &ProcessEntry)) {
        while (Process32Next(hSnap, &ProcessEntry)) {
            if (ProcessEntry.th32ParentProcessID == processID) { // if processID of the child Realtionship to the ParentID then it print ProcessID of child
                std::wcout << "Child Process PID: " << ProcessEntry.th32ProcessID << std::endl;
                outputfile << "          \"Child Process PID\": " << ProcessEntry.th32ProcessID << ",\n";
                haschildren = true;
            }
        }
    }
    if (!haschildren) {
        std::wcout << "No child processes." << std::endl;
        outputfile << "          \"Child Process PID\": \"None\",\n";
    }
    CloseHandle(hSnap);
}

int main() {
    DWORD aProcess[1024]; // array to store the process IDs
    DWORD cbNeeded;  // Returned by the EnumProcesses to store like number of bytes used by EnumProcesses 
    DWORD cProcesses; // number of process 

    std::wofstream outputfile("Process_info.json");
    if (!outputfile) {
        std::cerr << "Error: Unable to Capture the Event log :( "
            << "\nError -> File create error / Privilege Error";
        return 1;
    }

    std::cout << "Starting the Process scanning " << std::endl;
    outputfile << " {\n \"Process Logs\": [\n";

    if (!EnumProcesses(aProcess, sizeof(aProcess), &cbNeeded)) {   // to enumerate the process 
        std::cerr << "Error: EnumProcesses failed. Unable to fetch PIDs :( ." << std::endl;
        std::cerr << "Check if you have sufficient privileges or if the system is compatible :( ." << std::endl;
        return 1;
    }
    cProcesses = cbNeeded / sizeof(DWORD);  // taking the total length of the PID by reference of using cbneeded bytes stores by EnumProcessess
    std::cout << "Number of Processes: " << cProcesses << std::endl;

    outputfile << "Number of Processes Found: " << cProcesses << "\n";

    // Iterate through the processes 
    for (unsigned int i = 0; i < cProcesses; i++) {
        if (aProcess[i] != 0) {
            std::cout << "Process ID: " << aProcess[i] << std::endl;
            outputfile << "    {\n";
            outputfile << "      \"PID\": " << aProcess[i] << ",\n";

            // Getting the process name using ID
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, aProcess[i]);
            if (hProcess) {
                TCHAR sProcessName[MAX_PATH] = TEXT("");
                HMODULE hMod;
                DWORD cbneededName;

                if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbneededName)) {
                    GetModuleBaseName(hProcess, hMod, sProcessName, sizeof(sProcessName) / sizeof(TCHAR));
                }
                std::wcout << "Process Name: " << sProcessName << std::endl;
                outputfile << "      \"Name\": \"" << sProcessName << "\",\n";

                HMODULE hMods[1024]; // return the process name of each module
                DWORD cbModulesNeeded;

                if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbModulesNeeded)) {
                    DWORD numModules = cbModulesNeeded / sizeof(HMODULE);

                    std::cout << "Modules Loaded by the Process:" << std::endl;
                    outputfile << "       \"Modules Loaded by Process\": [\n";

                    for (DWORD j = 0; j < numModules; j++) {
                        TCHAR moduleName[1000];
                        if (GetModuleFileNameEx(hProcess, hMods[j], moduleName, sizeof(moduleName) / sizeof(TCHAR))) {
                            std::wcout << moduleName << std::endl;
                            outputfile << "        \"" << moduleName << "\"";
                            if (j < numModules - 1) {
                                outputfile << ",";
                            }
                            outputfile << "\n";
                        }
                    }
                }
                else {
                    std::cerr << "Error: Could not find the Modules for the Process." << std::endl;
                }

                // Call the function to enumerate child processes and print the output
                enumchildprocess(aProcess[i], outputfile);

                std::cout << "\n______________________________________________" << std::endl;
                outputfile << "    },\n";
            }
            else {
                std::cerr << "Unable to find the Process :( " << aProcess[i] << std::endl;
                std::cout << "______________________________________________\n" << std::endl;
            }
        }
    }
    outputfile << "]\n}";  // Close the JSON structure

    std::cout << "Process enumeration complete!" << std::endl;
    return 0;
}
