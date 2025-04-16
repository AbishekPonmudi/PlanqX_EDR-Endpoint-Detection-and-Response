// Writtent and tested by havox -> WinHttp code for Malware analysis using Online DB

#pragma once

#include <string>
#include <Windows.h>
#include <winhttp.h>
#include <iostream>
#include <vector>

#pragma comment(lib, "winhttp.lib")

std::string API_OP(const std::string& Filehash);