#pragma once

#include <iostream>
#include <string>

constexpr const char* inf = "[:)]";
constexpr const char* err = "[x]";

std::string GetErrorInfo(int errorCode) {
	switch (errorCode) {
	case 1:
		return std::string(err) + " File not found";
	case 2:
		return std::string(err) + " Permission issue";
	case 3:
		return std::string(err) + " Invalid input";
	case 4:
		return std::string(err) + " Folder not Found !";
	default:
		return std::string(inf) + " unknown Error ";
	}
}

