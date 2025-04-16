#pragma once

#include <iostream>
#include <string>
#include <Windows.h>
#include <unordered_set>
#include <nlohmann/json.hpp>
#include <fstream>
#include <Psapi.h>
#include <TlHelp32.h>

//using json = nlohmann::json;

void logToFile(const std::string& event, const std::string& filePath, DWORD ProcessID,const std::string& processname);
DWORD findProcessFromFile(const std::string& filePath);
std::wstring getProcessName(DWORD ProcessID);
void monitorDirectory(const std::string& directory);

