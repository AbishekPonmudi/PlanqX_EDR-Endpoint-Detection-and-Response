
// written and Tested by Havox 
// Leave the code here Just Tested Junk :( :| :)
/*
#include <iostream>
#include <fstream>
#include <cstdbool>
#include <filesystem>
#include <algorithm>
#include <Windows.h>
#include "errorcode.h"

int main(int argc , char* argv[]) {

	if (argc < 2) {
		std::cerr << "Error : Unable to find the folder name : " << GetErrorInfo(3) << std::endl;
		std::cerr << "Usage  : testing.exe << location >> " << std::endl;
		return 1;
	}
	//checking if the folder exist  
	std::string filepath = argv[1];

	if (!std::filesystem::exists(filepath)) {
		std::cerr << "Unable to find the folder location -> Errorcode : " << GetErrorInfo(4) << std::endl;
		return 1;
	}

	if (!std::filesystem::path(filepath).is_absolute()) {
		unsigned int Message = MessageBoxA(NULL, "Warning", "Error : Path must be absolute for security reason. ", MB_OK);
		return Message;
	}

	std::string folderpath = filepath + "/testing.txt";
	std::ofstream fout;
	std::string line;

	// file creating using ofstream
	//using fout to read the file and write the content to that file

	fout.open(folderpath);

	//code for creating the directory if That not exist 
	//if (!std::filesystem::exists(filepath)) {
		//std::filesystem::create_directories(filepath);
	//}

	if (!fout) {
		std::cerr << "Unble to create the file " << std::endl;
		return 1;
	}
	std::cout << "TO Exit Enter (type 'exit!') \n" << std::endl;


	while (true) {

		getline(std::cin, line);

		if (line == "exit!") {
			break;
		}
		fout << line << std::endl;
	}

	fout.close();

	std::cout << std::endl;
	std::string options;
	std::string options1;
	bool Fileout = false;

	std::cout << "[+]" << " To view the file Information Hit [y]/Yes else [n]/No to exit! : "; 
	std::cin >> options;
	std::cout << "[+]" << " To view the content in the file just Hit [y]/Yes else [n]/No : ";
	std::cout << std::endl;
	std::cin >> options1;
	std::transform(options.begin(), options.end(), options.begin(), ::tolower);
	std::transform(options1.begin(), options1.end(), options1.begin(), ::tolower);

	if (options != "y" && options != "yes" && options != "n" && options != "no") {
		std::cerr << "Invalid input. Please enter 'y', 'yes', 'n', or 'no'." << std::endl;
		return 1;
	}

	if (options1 == "y" || options1 == "yes") {
		Fileout = true;
	} 

	if (options == "y" || options == "yes") {

		std::ifstream fin;
		fin.open(folderpath);

		if (!fin) {
			std::cout << "Unable to find the file " << std::endl;
			return 1;
		}

		
		//reading the file in the current created file

		unsigned int count = 0;
		unsigned int size = 1;


		while (getline(fin, line)) {

			count++;
			size += line.size();
			if (Fileout) {
				std::cout << line << std::endl;
			}
			
		}

		if (size == 0) {
			std::cerr << "No content : File is empty.. " << std::endl;
			return 1;
		}

		std::cout << std::endl;
		std::cout << "Totally Characters : " << size << std::endl;
		std::cout << "Totall lines : " << count << std::endl;

		fin.close();
	}
	return 0;
}	

	*/		

/**
#include <windows.h>
#include <winhttp.h>
#include <iostream>
#include <string>

#pragma comment(lib, "winhttp.lib")

int main() {
	// Initialize session
	HINTERNET hSession = WinHttpOpen(L"WinHTTP Example/1.0",
		WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
		WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS, 0);

	std::string apihash = "992d48d2cf51f5c699304f4df94e969fc5149bf2b7201002049ebd1ed828be6b";

	if (hSession) {
		// Specify the server and URL path
		HINTERNET hConnect = WinHttpConnect(hSession, L"mb-api.abuse.ch", INTERNET_DEFAULT_HTTPS_PORT, 0);
		if (hConnect) {
			HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/api/v1/", NULL,
				WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
				WINHTTP_FLAG_SECURE);

			if (hRequest) {
				// Add headers
				const wchar_t* headers = L"Content-Type: application/x-www-form-urlencoded\r\n"
					L"Auth-Key:eca393be6faa22f08882c3cc5a9b1702ce1f1b8727165bd6";
				std::string postData = "query=get_info&hash="+ apihash;

				// Send request
				BOOL result = WinHttpSendRequest(hRequest,
					headers, -1L, // Use -1L to let WinHTTP calculate header length
					(LPVOID)postData.c_str(),
					(DWORD)postData.size(),
					(DWORD)postData.size(), 0);

				if (result) {
					if (WinHttpReceiveResponse(hRequest, NULL)) {
						DWORD dwSize = 0;
						DWORD bytesRead = 0;
						do {
							WinHttpQueryDataAvailable(hRequest, &dwSize);
							if (dwSize > 0) {
								char* buffer = new char[dwSize + 1];
								ZeroMemory(buffer, dwSize + 1);
								WinHttpReadData(hRequest, buffer, dwSize, &bytesRead);
								std::cout << "Response: " << buffer << std::endl;
								delete[] buffer;
							}
						} while (dwSize > 0);
					}
					else {
						std::cerr << "Failed to receive response: " << GetLastError() << std::endl;
					}
				}
				else {
					std::cerr << "Failed to send request: " << GetLastError() << std::endl;
				}

				WinHttpCloseHandle(hRequest);
			}
			else {
				std::cerr << "Failed to open HTTP request: " << GetLastError() << std::endl;
			}

			WinHttpCloseHandle(hConnect);
		}
		else {
			std::cerr << "Failed to connect to server: " << GetLastError() << std::endl;
		}

		WinHttpCloseHandle(hSession);
	}
	else {
		std::cerr << "Failed to initialize WinHTTP session: " << GetLastError() << std::endl;
	}

	return 0;
}
*/

// code to analyse and monitoring the file / application running process and imports

//#include <windows.h>
//#include <iostream>
//#include <fstream>
//#include <string>
//#include <nlohmann/json.hpp>
//#include <unordered_set>
//#include <Psapi.h>
//
//using json = nlohmann::json;
//
//std::unordered_set<std::string> loggedFiles;
//
//void logToFile(const std::string& event, const std::string& filePath) {
//
//	if (loggedFiles.find(filePath) != loggedFiles.end()) {
//		return;  
//	}
//
//	json logEntry;
//	logEntry["event"] = event;
//	logEntry["filePath"] = filePath;
//	logEntry["timestamp"] = GetTickCount();
//
//	// Log the entry
//	std::ofstream logFile("file_monitor.json", std::ios::app);
//	logFile << logEntry.dump(4) << std::endl;
//	logFile.close();
//
//	loggedFiles.insert(filePath);
//}
//
//void monitorDirectory(const std::string& directory) {
//
//	std::wstring wDirectory(directory.begin(), directory.end());
//
//	HANDLE hDir = CreateFile(
//		wDirectory.c_str(),
//		FILE_LIST_DIRECTORY,
//		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
//		NULL,
//		OPEN_EXISTING,
//		FILE_FLAG_BACKUP_SEMANTICS,
//		NULL);
//
//	if (hDir == INVALID_HANDLE_VALUE) {
//		std::cerr << "Failed to open directory: " << directory << std::endl;
//		return;
//	}
//
//	char buffer[1024];
//	DWORD bytesReturned;
//	FILE_NOTIFY_INFORMATION* notification;
//
//	while (true) {
//		if (ReadDirectoryChangesW(
//			hDir, buffer, sizeof(buffer), TRUE,
//			FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_SIZE |
//			FILE_NOTIFY_CHANGE_LAST_WRITE,
//			&bytesReturned, NULL, NULL)) {
//			notification = (FILE_NOTIFY_INFORMATION*)buffer;
//			do {
//				std::wstring fileName(notification->FileName,
//					notification->FileNameLength / sizeof(WCHAR));
//				std::string filePath(fileName.begin(), fileName.end());
//
//				switch (notification->Action) {
//				case FILE_ACTION_ADDED:
//					logToFile("Created", filePath);
//					break;
//				case FILE_ACTION_REMOVED:
//					logToFile("Deleted", filePath);
//					break;
//				case FILE_ACTION_MODIFIED:
//					logToFile("Modified", filePath);
//					break;
//				case FILE_ACTION_RENAMED_OLD_NAME:
//					logToFile("Renamed (Old)", filePath);
//					break;
//				case FILE_ACTION_RENAMED_NEW_NAME:
//					logToFile("Renamed (New)", filePath);
//					break;
//				}
//				notification = notification->NextEntryOffset
//					? (FILE_NOTIFY_INFORMATION*)((BYTE*)notification +
//						notification->NextEntryOffset)
//					: nullptr;
//			} while (notification);
//		}
//	}
//
//	CloseHandle(hDir);
//}

#include <string>
#include "File-App_mon.h"
#include <nlohmann/json.hpp>

int main() {
	std::string directory = "C:\\";
	monitorDirectory(directory);
	return 0;
}
