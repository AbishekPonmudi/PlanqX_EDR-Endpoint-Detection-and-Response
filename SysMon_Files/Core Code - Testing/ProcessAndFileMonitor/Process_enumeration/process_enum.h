#pragma once

#include <Windows.h>
#include <Psapi.h>
#include <iostream>
#include <tchar.h>
#include <fstream>
#include <TlHelp32.h>  // for createToolhelp32snapshot
#pragma comment(lib, "Psapi.lib")

void enumchildprocess(DWORD processID, std::wofstream& outputfile);
void EnumProcessId();