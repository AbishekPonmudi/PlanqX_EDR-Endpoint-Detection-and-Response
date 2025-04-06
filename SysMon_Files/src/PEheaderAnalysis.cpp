/*   @Planqx EDR -	PEheaderanalysis  this Code Which analyse the PE structure of the file for suscipious API and imports :)
 *									@Author : Written By @Havox :)

 *    Permission is hereby granted, free of charge, to any person obtaining
 *    this piece of code, and you can deal in the Software without restriction,
 *    including without limitation the rights to use and modify and to permit
 *	  persons to whom the Software is furnished to do so,subject to the following
 *	  conditions:
 *
 *    The above copyright notice and this permission notice shall be included
 *    in all copies or substantial portions of the Software.
 *
 *    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 *    OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *    MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 *    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 *    CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 *    TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 *    SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include "PEheaderAnalysis.h"
#include <iostream>
#include <Windows.h>
#include <Psapi.h>
#include <string>
#pragma comment(lib,"Psapi.lib")

void PrintImportsAPI(DWORD processID) {
	// opening the process to enum the DLL and modules imported
	HANDLE hprocess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
	if (hprocess == nullptr) {
		std::cout << "[!] Failed to Open the Process => " << GetLastError() << std::endl;
		return;
	}
	HMODULE Hmod[1024];
	DWORD cNeeded;

	// Enum the Modules fromt he Process
	if (!EnumProcessModules(hprocess, Hmod, sizeof(Hmod), &cNeeded)) {
		std::cout << "[!] Failed to Enumerate the Modules => " << GetLastError() << std::endl;
		CloseHandle(hprocess);
		return;
	}

	DWORD hSize = cNeeded / sizeof(HMODULE);
	for (unsigned int i = 0; i < hSize; i++) {
		TCHAR szModName[MAX_PATH];
		if (GetModuleFileNameEx(hprocess, Hmod[i], szModName, MAX_PATH)) {
			std::cout << std::endl;
			std::wcout << "[*]" << L"Module: " << szModName << std::endl;
			std::cout << std::endl;

			//load the module into memory to enum the imported API first parse the PE structure

			HANDLE hfile = CreateFile(szModName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
			if (hfile == INVALID_HANDLE_VALUE) {
				std::cout << "[!] Could not open File => " << GetLastError() << std::endl;
				CloseHandle(hfile);
				continue;;
			}

			// mapping the hfile to map the files into the process address space for efficent analysis rather then I/O operation
			HANDLE hMapping = CreateFileMapping(hfile, NULL, PAGE_READONLY, 0, 0, NULL);
			if (hMapping == NULL) {
				std::cout << "[!] Creating Mapping into memory Failed => " << GetLastError() << std::endl;
				CloseHandle(hMapping);
				continue;;
			}


			/* ACTUAL FLOW how PE Header works look before analysing this code
				DOS_HEADER -> e_lfanew -> NT_HEADERS
											├── FILE_HEADER
											├── OPTIONAL_HEADER -> ImageBase
											├── DataDirectory[IMPORT] -> importRVA
													├── importDesc (Import Table)
													│      ├── DLL Names
													│      ├── Function Names (Thunk Table)

			  */

			  // opeing the mapped memory to enumerate the API imported, actually this is an absolute addredd (starting address) where PE mapped to memory
			LPVOID lpBase = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);

			if (lpBase == nullptr) {
				std::cout << "[!] Failed to open the Mapped from memory => " << GetLastError() << std::endl;
				CloseHandle(lpBase);
				continue;;
			}

			// Let's start to parse the PE file to enum the Actual API's :) -> interesting part

			PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)lpBase;
			if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) { // 0x5D4A => MZ to check the signature (if condition False)
				std::cout << "[!] Invalid DOS signature => " << GetLastError() << std::endl;
				UnmapViewOfFile(lpBase);
				CloseHandle(hMapping);
				CloseHandle(hfile);
				continue;;
			}

			// using NT_Headers to get the optional header to get the ImageBase as entry point to access the import table & address table
			// for that we accessing via DOS_Header's e_lfanew contains the offset to NT_HEADER by adding the offset to the base of the file....
			// ...lpbase to get the actual address of NT_HEADER

			PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)((BYTE*)lpBase + dosHeader->e_lfanew);
			if (NtHeader->Signature != IMAGE_NT_SIGNATURE) {
				std::cout << "[!] Invalid NT Signature => " << std::endl;
				UnmapViewOfFile(lpBase);
				CloseHandle(hMapping);
				CloseHandle(hfile);
				continue;
			}

			// Next ! Here the important part of this code that, to enum the Import from the NT_HEADER->OPTIONAL_HEADER we using..... 
			// ....IMAGE_DIRECTORY_ENTRY_IMPORT, for that we retrive the RVA (Relative address table) from the data directory in the optional header
			// ....here we simply getting the RVA address not the actual address 
			// 

			DWORD importRVA = NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
			if (importRVA == 0) {
				std::cout << "[!] No Imports Found" << std::endl;
				UnmapViewOfFile(hMapping);
				CloseHandle(hfile);
				CloseHandle(hMapping);
				continue;
			}

			// Now we have to export the modules but we actually need the actual address, Don't we have the importRVA addredd so add....
			// .....that to get the actual memory pointer 
			// 
			// get to understand see the flow on top 

			PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)lpBase + importRVA);
			while (importDesc->Name != 0) {
				const char* dllName = (const char*)((BYTE*)lpBase + importDesc->Name);
				std::cout << "	DLL: " << dllName << std::endl;

				// the FirstThunk if just a Placeholder, Means that have the offser address of function like 
				// ...0x2000 (Placeholder) -> initially both "FirstThunk and OriginalFirstThunk" seems same but....
				//							  ....firstThunk change with actual memory after resolution
				PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE*)lpBase + importDesc->FirstThunk);

				// but originalFirstThunk have the actual naem of the function like this 
				//...."CreateProcessA"  →  RVA: 0x2000
				PIMAGE_THUNK_DATA origTrunk = (PIMAGE_THUNK_DATA)((BYTE*)lpBase + importDesc->OriginalFirstThunk);
				if (!origTrunk) origTrunk = thunk; // if orignalThunk if empty just refer thunk because we have actual address so get from that Firztthunk


				// Ooooo! we going to get the API imported here

				while (origTrunk->u1.AddressOfData != 0) {
					if (!(origTrunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {

						PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)lpBase + origTrunk->u1.AddressOfData);
						std::cout << "		   API: " << importByName->Name << std::endl;
					}
					origTrunk++;
				}
				importDesc++;
			}
			UnmapViewOfFile(lpBase);
			CloseHandle(hfile);
			CloseHandle(hMapping);
		}
	}
	CloseHandle(hprocess);

}

int main() {
	DWORD Pid;
	std::cout << "Enter the Process ID: ";
	std::cin >> Pid;
	PrintImportsAPI(Pid);
	return 0;
}
