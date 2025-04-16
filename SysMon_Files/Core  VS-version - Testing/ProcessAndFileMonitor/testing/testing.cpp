
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

//#include <string>
//#include "File-App_mon.h"
//#include <nlohmann/json.hpp>
//
//int main() {
//	std::string directory = "C:\\";
//	monitorDirectory(directory);
//	return 0;
//}

//#include <iostream>
//#include <windows.h>
//#include <string.h>
//
//namespace planqx = std;
//using namespace planqx;
//
//#define Round RWERF
//typedef DWORD PlDword;
//
//
//#define DEBUG
//
//#ifdef DEBUG
//void debug_message() {
//	std::cout << "Debug mode is ON\n";
//}
//#endif
//
//int main() {
//#ifdef DEBUG
//	debug_message();
//#endif
//}

//#include <iostream>
//#include <Windows.h>
//#include <Psapi.h>
//#include <string>
//#pragma comment(lib,"Psapi.lib")
//
//void PrintImportsAPI(DWORD processID) {
//	// opening the process to enum the DLL and modules imported
//	HANDLE hprocess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
//		if (hprocess == nullptr) {
//			std::cout << "[!] Failed to Open the Process => "<< GetLastError() << std::endl;
//			return;
//		}
//		HMODULE Hmod[1024];
//		DWORD cNeeded;
//
//		// Enum the Modules fromt he Process
//		if (!EnumProcessModules(hprocess, Hmod, sizeof(Hmod), &cNeeded)) {
//			std::cout << "[!] Failed to Enumerate the Modules => " << GetLastError() << std::endl;
//			CloseHandle(hprocess);
//			return;
//		}
//
//		DWORD hSize = cNeeded / sizeof(HMODULE);
//		for (unsigned int i = 0; i < hSize; i++) {
//			TCHAR szModName[MAX_PATH];
//			if (GetModuleFileNameEx(hprocess, Hmod[i], szModName, MAX_PATH)) {
//				std::wcout <<"[*]" << L"Module: " << szModName << std::endl;
//
//				//load the module into memory to enum the imported API first parse the PE structure
//
//				HANDLE hfile = CreateFile(szModName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
//				if (hfile == INVALID_HANDLE_VALUE) {
//					std::cout << "[!] Could not open File => " << GetLastError() << std::endl;
//					CloseHandle(hfile);
//					continue;;
//				}
//
//				// mapping the hfile to map the files into the process address space for efficent analysis rather then I/O operation
//				HANDLE hMapping = CreateFileMapping(hfile, NULL, PAGE_READONLY, 0, 0, NULL);
//					if (hMapping == NULL) { 
//						std::cout << "[!] Creating Mapping into memory Failed => " << GetLastError() << std::endl;
//						CloseHandle(hMapping);
//						continue;;
//					}
//
//
//					/* ACTUAL FLOW how PE Header works look before analysing this code
//						DOS_HEADER -> e_lfanew -> NT_HEADERS
//													├── FILE_HEADER
//													├── OPTIONAL_HEADER -> ImageBase
//													├── DataDirectory[IMPORT] -> importRVA
//															├── importDesc (Import Table)
//															│      ├── DLL Names
//															│      ├── Function Names (Thunk Table)
//
//					  */
//
//				// opeing the mapped memory to enumerate the API imported, actually this is an absolute addredd (starting address) where PE mapped to memory
//				LPVOID lpBase = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
//
//					if (lpBase == nullptr) {
//						std::cout << "[!] Failed to open the Mapped from memory => " << GetLastError() << std::endl;
//						CloseHandle(lpBase);
//						continue;;
//					}
//
//				// Let's start to parse the PE file to enum the Actual API's :) -> interesting part
//
//					PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)lpBase;
//					if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) { // 0x5D4A => MZ to check the signature (if condition False)
//						std::cout << "[!] Invalid DOS signature => " << GetLastError() << std::endl;
//						UnmapViewOfFile(lpBase);
//						CloseHandle(hMapping);
//						CloseHandle(hfile);
//						continue;;
//					}
//
//					// using NT_Headers to get the optional header to get the ImageBase as entry point to access the import table & address table
//					// for that we accessing via DOS_Header's e_lfanew contains the offset to NT_HEADER by adding the offset to the base of the file....
//					// ...lpbase to get the actual address of NT_HEADER
//
//					PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)((BYTE*)lpBase + dosHeader->e_lfanew);
//					if (NtHeader->Signature != IMAGE_NT_SIGNATURE) {
//						std::cout << "[!] Invalid NT Signature => " << std::endl;
//						UnmapViewOfFile(lpBase);
//						CloseHandle(hMapping);
//						CloseHandle(hfile);
//						continue;
//					}
//
//					// Next ! Here the important part of this code that, to enum the Import from the NT_HEADER->OPTIONAL_HEADER we using..... 
//					// ....IMAGE_DIRECTORY_ENTRY_IMPORT, for that we retrive the RVA (Relative address table) from the data directory in the optional header
//					// ....here we simply getting the RVA address not the actual address 
//					// 
//
//					DWORD importRVA = NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
//					if (importRVA == 0) {
//						std::cout << "[!] No Imports Found" << std::endl;
//						UnmapViewOfFile(hMapping);
//						CloseHandle(hfile);
//						CloseHandle(hMapping);
//						continue;
//					}
//
//					// Now we have to export the modules but we actually need the actual address, Don't we have the importRVA addredd so add....
//					// .....that to get the actual memory pointer 
//					// 
//					// get to understand see the flow on top 
//
//					PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)lpBase + importRVA);
//					while (importDesc->Name != 0) {
//						const char* dllName = (const char*)((BYTE*)lpBase + importDesc->Name);
//						std::cout << "DLL: " << dllName << std::endl;
//
//						// the FirstThunk if just a Placeholder, Means that have the offser address of function like 
//						// ...0x2000 (Placeholder) -> initially both "FirstThunk and OriginalFirstThunk" seems same but....
//						//							  ....firstThunk change with actual memory after resolution
//						PIMAGE_THUNK_DATA thunk= (PIMAGE_THUNK_DATA)((BYTE*)lpBase + importDesc->FirstThunk);
//
//						// but originalFirstThunk have the actual naem of the function like this 
//						//...."CreateProcessA"  →  RVA: 0x2000
//						PIMAGE_THUNK_DATA origTrunk = (PIMAGE_THUNK_DATA)((BYTE*)lpBase + importDesc->OriginalFirstThunk);
//						if (!origTrunk) origTrunk = thunk; // if orignalThunk if empty just refer thunk because we have actual address so get from that Firztthunk
//						
//
//						// Ooooo! we going to get the API imported here
//
//						while (origTrunk->u1.AddressOfData != 0) {
//							if (!(origTrunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
//
//								PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)lpBase + origTrunk->u1.AddressOfData);
//								std::cout << "	    API: " << importByName->Name << std::endl;
//							}
//							origTrunk++;
//						}
//						importDesc++;
//					}
//					UnmapViewOfFile(lpBase);
//					CloseHandle(hfile);
//					CloseHandle(hMapping);
//			}
//		}
//		CloseHandle(hprocess);
//		
//	}
//
//int main() {
//	DWORD Pid;
//	std::cout << "Enter the Process ID: ";
//	std::cin >> Pid;
//	PrintImportsAPI(Pid);
//	return 0;
//}


//#in before method 


//#include <iostream>
//#include <Windows.h>
//#include <Psapi.h>
//#include <TlHelp32.h>
//#include <string>
//#pragma comment(lib, "Psapi.lib")
//
//// Enable SeDebugPrivilege for accessing all processes
//BOOL EnableDebugPrivilege() {
//    HANDLE hToken;
//    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
//        std::cout << "[!] Failed to open process token => " << GetLastError() << std::endl;
//        return FALSE;
//    }
//
//    TOKEN_PRIVILEGES tp;
//    tp.PrivilegeCount = 1;
//    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
//    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid)) {
//        std::cout << "[!] Failed to lookup privilege => " << GetLastError() << std::endl;
//        CloseHandle(hToken);
//        return FALSE;
//    }
//
//    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
//        std::cout << "[!] Failed to adjust privilege => " << GetLastError() << std::endl;
//        CloseHandle(hToken);
//        return FALSE;
//    }
//
//    CloseHandle(hToken);
//    return TRUE;
//}
//
//// Analyze imports for a single module in the process's memory
//
///* ACTUAL FLOW how PE Header works look before analysing this code
//				DOS_HEADER -> e_lfanew -> NT_HEADERS
//											├── FILE_HEADER
//											├── OPTIONAL_HEADER -> ImageBase
//											├── DataDirectory[IMPORT] -> importRVA
//													├── importDesc (Import Table)
//													│      ├── DLL Names
//													│      ├── Function Names (Thunk Table)
//
//			  */
//
//void AnalyzeModuleImports(HANDLE hProcess, HMODULE hModule, const TCHAR* moduleName) {
//
//    std::wcout << L"\n[*] Module: " << moduleName << std::endl;
//
//    // Dynamically allocate buffers to avoid stack overflow
//    BYTE* dosBuffer = new BYTE[sizeof(IMAGE_DOS_HEADER)];
//    SIZE_T bytesRead;
//
//    // Read DOS header
//    if (!ReadProcessMemory(hProcess, hModule, dosBuffer, sizeof(IMAGE_DOS_HEADER), &bytesRead)) {
//        std::cout << "[!] Failed to read DOS header => " << GetLastError() << std::endl;
//        delete[] dosBuffer;
//        return;
//    }
//
//	// Let's start to parse the PE file to enum the Actual API's :) -> interesting part
//
//    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dosBuffer;
//    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
//        std::cout << "[!] Invalid DOS signature" << std::endl;
//        delete[] dosBuffer;
//        return;
//    }
//
//    // Read NT header
//    BYTE* ntBuffer = new BYTE[sizeof(IMAGE_NT_HEADERS)];
//    if (!ReadProcessMemory(hProcess, (BYTE*)hModule + dosHeader->e_lfanew, ntBuffer, sizeof(IMAGE_NT_HEADERS), &bytesRead)) {
//        std::cout << "[!] Failed to read NT header => " << GetLastError() << std::endl;
//        delete[] dosBuffer;
//        delete[] ntBuffer;
//        return;
//    }
//
//	// using NT_Headers to get the optional header to get the ImageBase as entry point to access the import table & address table
//			// for that we accessing via DOS_Header's e_lfanew contains the offset to NT_HEADER by adding the offset to the base of the file....
//			// ...lpbase to get the actual address of NT_HEADER
//
//    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)ntBuffer;
//    if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
//        std::cout << "[!] Invalid NT signature" << std::endl;
//        delete[] dosBuffer;
//        delete[] ntBuffer;
//        return;
//    }
//
//	// Next ! Here the important part of this code that, to enum the Import from the NT_HEADER->OPTIONAL_HEADER we using..... 
//			// ....IMAGE_DIRECTORY_ENTRY_IMPORT, for that we retrive the RVA (Relative address table) from the data directory in the optional header
//			// ....here we simply getting the RVA address not the actual address 
//			// 
//
//    DWORD importRVA = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
//    if (importRVA == 0) {
//        std::cout << "[!] No Imports Found" << std::endl;
//        delete[] dosBuffer;
//        delete[] ntBuffer;
//        return;
//    }
//
//    // Read import directory
//    BYTE* importBuffer = new BYTE[4096]; // Adjust size as needed
//    if (!ReadProcessMemory(hProcess, (BYTE*)hModule + importRVA, importBuffer, 4096, &bytesRead)) {
//        std::cout << "[!] Failed to read import table => " << GetLastError() << std::endl;
//        delete[] dosBuffer;
//        delete[] ntBuffer;
//        delete[] importBuffer;
//        return;
//    }
//
//	// Now we have to export the modules but we actually need the actual address, Don't we have the importRVA addredd so add....
//			// .....that to get the actual memory pointer 
//			// 
//			// get to understand see the flow on top 
//
//
//    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)importBuffer;
//    while (importDesc->Name != 0) {
//        // Read DLL name
//        char* dllName = new char[256];
//        if (!ReadProcessMemory(hProcess, (BYTE*)hModule + importDesc->Name, dllName, 256, &bytesRead)) {
//            std::cout << "[!] Failed to read DLL name => " << GetLastError() << std::endl;
//            delete[] dllName;
//            break;
//        }
//        dllName[bytesRead < 256 ? bytesRead : 255] = '\0'; // Ensure null termination
//        std::cout << "    DLL: " << dllName << std::endl;
//
//        // Read thunk data
//        BYTE* thunkBuffer = new BYTE[4096];
//        DWORD thunkRVA = importDesc->OriginalFirstThunk ? importDesc->OriginalFirstThunk : importDesc->FirstThunk;
//        if (!ReadProcessMemory(hProcess, (BYTE*)hModule + thunkRVA, thunkBuffer, 4096, &bytesRead)) {
//            std::cout << "[!] Failed to read thunk data => " << GetLastError() << std::endl;
//            delete[] dllName;
//            delete[] thunkBuffer;
//            break;
//        }
//
//        PIMAGE_THUNK_DATA thunkData = (PIMAGE_THUNK_DATA)thunkBuffer;
//        int j = 0;
//        while (thunkData[j].u1.AddressOfData != 0) {
//            if (thunkData[j].u1.Ordinal & IMAGE_ORDINAL_FLAG) {
//                std::cout << "        API: Ordinal " << (thunkData[j].u1.Ordinal & 0xFFFF) << std::endl;
//            }
//            else {
//                BYTE* nameBuffer = new BYTE[256];
//                if (!ReadProcessMemory(hProcess, (BYTE*)hModule + thunkData[j].u1.AddressOfData, nameBuffer, 256, &bytesRead)) {
//                    std::cout << "[!] Failed to read import name => " << GetLastError() << std::endl;
//                    delete[] nameBuffer;
//                    break;
//                }
//                PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)nameBuffer;
//                std::cout << "        API: " << importByName->Name << std::endl;
//                delete[] nameBuffer;
//            }
//            j++;
//        }
//        delete[] dllName;
//        delete[] thunkBuffer;
//        importDesc++;
//    }
//
//    // Clean up
//    delete[] dosBuffer;
//    delete[] ntBuffer;
//    delete[] importBuffer;
//}
////malware_learn
//// Enumerate imports for all modules in a process
//void PrintImportsAPI(DWORD processID) {
//
//    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
//    if (hProcess == nullptr) {
//        std::cout << "[!] Failed to open process " << processID << " => " << GetLastError() << std::endl;
//        return;
//    }
//
//    HMODULE hMods[1024];
//    DWORD cbNeeded;
//    if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
//        std::cout << "[!] Failed to enumerate modules for PID " << processID << " => " << GetLastError() << std::endl;
//        CloseHandle(hProcess);
//        return;
//    }
//
//    DWORD modCount = cbNeeded / sizeof(HMODULE);
//    for (DWORD i = 0; i < modCount; i++) {
//        TCHAR szModName[MAX_PATH];
//        if (GetModuleFileNameEx(hProcess, hMods[i], szModName, MAX_PATH)) {
//            AnalyzeModuleImports(hProcess, hMods[i], szModName);
//        }
//    }
//    CloseHandle(hProcess);
//}
//
//
//int main() {
//    // Elevate privileges
//    if (!EnableDebugPrivilege()) {
//        std::cout << "[!] Warning: Could not enable SeDebugPrivilege. Some processes may be inaccessible." << std::endl;
//    }
//
//        DWORD pid;
//        std::cout << "Enter the Process ID: ";
//        std::cin >> pid;
//        PrintImportsAPI(pid);
//  
//    return 0;
//}