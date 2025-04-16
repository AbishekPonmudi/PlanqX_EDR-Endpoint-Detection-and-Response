#pragma once

#include <iostream>
#include <string>

#define str std::string

const char* info = "[:)]";
const char* error = "[x]";

std::string GetErrorInfo(int errorCode) {
	switch (errorCode) {
	case 1:
		return std::string(error) + "File not found";
	case 2:
		return std::string(error) + "Permission issue";
	case 3:
		return std::string(error) + "Invalid input";
	default:
		return std::string(info) + "unknown Error ";
	}
}

