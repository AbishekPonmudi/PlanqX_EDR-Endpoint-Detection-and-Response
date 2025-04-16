#pragma once

#include <iostream>
#include <Windows.h>
#include <Psapi.h>
#include <tchar.h>
#include <AclAPI.h>
#include <fstream>
#include <TlHelp32.h>
#include <string>
#pragma comment(lib, "Psapi.lib")

void checkProcessIntegrety(HANDLE hProcess);
BOOL EnableDebugPrivilege();
void AnalyzeModuleImports(HANDLE hProcess, HMODULE hModule, const TCHAR* moduleName, std::wofstream& outfile);
void PrintImportsAPI(DWORD processID, std::wofstream& outFile);



