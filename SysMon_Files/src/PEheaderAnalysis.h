
#pragma once

#include <iostream>
#include <Windows.h>
#include <Psapi.h>
#include <string>
#pragma comment(lib,"Psapi.lib")

void PrintImportsAPI(DWORD processID);