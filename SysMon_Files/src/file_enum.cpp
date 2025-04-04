// written and tested by havox @cp OG

// this tool enum the file and scan with IOC of hashes to find any malicious files

#include <windows.h>
#include <iostream>
#include <string>
#include <filesystem>
#include <wincrypt.h>
#include <fstream>
#include <sstream>
#include <cstddef> // for std::byte
#include <iomanip>
#include <unordered_set>
#include <fstream>
#include <algorithm>
#include <winhttp.h>
#include <chrono>
#include <ctime>
#include <stdbool.h>
#include <nlohmann/json.hpp>
#include "ApiOperation.h"
#include "errorcode.h"

#define SHA256_DIGEST_LENGTH 32
#define DEFAULT_SIZE 100

using json = nlohmann::json ;
namespace fs = std::filesystem;
using namespace std;

const char* okay = "[*]";
const char* error = "[-]";
const char* info = "[+]";

// function used to convert the file into SHA-256 hash
std::string computerHash(const std::string& filepath) {

// object to handle the from file
	HCRYPTPROV hcryptoprov;
	HCRYPTHASH hHash;
	const size_t buffer_size = 4096;  // declearing the buffer size as 4kB to read efficiently
	char buffer[buffer_size];
	BYTE hash[SHA256_DIGEST_LENGTH];
	DWORD hashsize = SHA256_DIGEST_LENGTH;

	/*std::string path = filepath;
	HANDLE hFile = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);*/

	std::ifstream file(filepath, std::ios::binary);

	if (!file.is_open()) {
		std::cout << error << " Error opening the File " << GetLastError() << std::endl;
		return ""; // return nothing instead of 1 due to string
	} 	
	// used of the crypto converting content 
	if (!CryptAcquireContext(&hcryptoprov, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
		std::cerr << " Error occur in cryptographic content " << GetLastError() << std::endl;
		return "";
	}
	//used for hash conversion from file 
	if (!CryptCreateHash(hcryptoprov, CALG_SHA_256, 0, 0, &hHash)) {
		std::cerr << " Error occur in Hash object " << GetLastError() << std::endl;
		CryptReleaseContext(hcryptoprov, 0);
		return "";
	}

	// read the file and hash it with buffer size
	while (file.read(buffer, buffer_size)) {
		if (!CryptHashData(hHash, reinterpret_cast<BYTE*>(buffer), file.gcount(), 0)) {
			std::cerr << " Error hashing data " << std::endl;
			// to avoid unnecessary error after the Error acquired Remove the generetad hash
				CryptDestroyHash(hHash);
				CryptReleaseContext(hcryptoprov, 0);
				return "";
		}
	}
	// handle remaining data on the file 
	if (file.gcount() > 0) { // Handle remaining bytes
		if (!CryptHashData(hHash, reinterpret_cast<BYTE*>(buffer), file.gcount(), 0)) {
			std::cerr << error << " Error hashing remaining data. Error code: " << GetLastError() << std::endl;
			CryptDestroyHash(hHash);
			CryptReleaseContext(hcryptoprov, 0);
			return "";
		}
	}

	if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashsize, 0)) {
		std::cerr << error << " Error getting Hash value" << std::endl;
		CryptDestroyHash(hHash);
		CryptReleaseContext(hcryptoprov, 0);
		return "";
	}
	//converting hash to hex string
	std::ostringstream strstm;
	for (unsigned int i = 0; i < hashsize; i++) {
		strstm << std::setw(2) << std::setfill('0') << std::hex << (int)hash[i];
	}
	//close all decleared value
	CryptDestroyHash(hHash);
	CryptReleaseContext(hcryptoprov, 0);
	return strstm.str();
}

//locading all the local hashes into the Set To Find hashes fastly like cache

std::unordered_set<std::string> LocalDatabase(const std::string& LocalDB) {
	std::unordered_set<std::string> hashset;
	std::ifstream Fstrm;
	Fstrm.open(LocalDB);
	std::string line;	
	while (getline(Fstrm, line)) {
		hashset.insert(line);
	}
	return hashset;
}

void GenerateReport(const nlohmann::json& scaninfo, const nlohmann::json& Malinfo) {
						
	std::ofstream ScanSummary("Scan_summanry.json");
	std::ofstream MalwareDetect("Malware_detect_Summary.json");

	if (ScanSummary.is_open()) {
		ScanSummary << scaninfo.dump(4);
		ScanSummary.close();
	}
	if (MalwareDetect.is_open()) {
		MalwareDetect << Malinfo.dump(4);
		MalwareDetect.close();
	}
}
void FolderEnum(const std::string filepath, const std::unordered_set<std::string>& LocalDB, const std::string& user) {

	// Declaring arrays to store scan info for JSON format
	nlohmann::json MaldecSummary = nlohmann::json::array();
	nlohmann::json scanSummary = nlohmann::json::array();

	std::string time;

	nlohmann::json ScanFileCombine;
	ScanFileCombine["Pc name"] = user;
	ScanFileCombine["Path"] = filepath;
	ScanFileCombine["Scan details"] = {
		{"start_time", time},
		{"Scan Type", "Full Scan"},
		{"Scan Spot", "Server Testing"}
	};


	for (const auto& Fscan : std::filesystem::recursive_directory_iterator(filepath, std::filesystem::directory_options::skip_permission_denied)) {

		if (std::filesystem::is_regular_file(Fscan.path())) {
			std::string scanpath = Fscan.path().string();
			std::string Filehash = computerHash(scanpath);

			// to calculate the starting time of the file scaanning 

			std::chrono::time_point<std::chrono::system_clock> end = std::chrono::system_clock::now();
			std::time_t scan_time = std::chrono::system_clock::to_time_t(end);
			char Time_buffer[26];
			ctime_s(Time_buffer, sizeof(Time_buffer), &scan_time);
			//converting buffer to string 

			std::string Start_Time = Time_buffer;
			time = Time_buffer ;
			//removing new character
			Start_Time.pop_back();

			// for API detection staus 
			BOOL API_status = FALSE;

			if (LocalDB.find(Filehash) != LocalDB.end()) {
				nlohmann::json MalwareDecinfo = {
					{"File Path", scanpath},
					{"SHA-256 Hash", Filehash},
					{"Scan Time",Start_Time}
				};
				MaldecSummary.push_back(MalwareDecinfo);
			}
			else {
				try {
					std::string response = API_OP(Filehash);

					try {
						std::cout << std::endl;

						// Written out for testing purpose 
						std::cerr << "Raw API Response: " << response << std::endl;

						auto jsonResponse = nlohmann::json::parse(response);

						if (jsonResponse.contains("query_status")) {
							std::string status = jsonResponse["query_status"];
							if (status == "ok") {
								API_status = TRUE;
								nlohmann::json API_response = {
									{"File Path",filepath},
									{"File Hash", Filehash},
									{"Scan time", Start_Time},
									{"API Reply", "Detected"},
									{"API Response", jsonResponse}
								};
								MaldecSummary.push_back(API_response);
							}
							else if (status == "hash_not_found") {
								std::cerr << "Hash not found in the database." << std::endl;
							}
							else {
								std::cerr << "Unexpected query status: " << status << std::endl;
							}
						}
						else {
							std::cerr << "API response does not contain 'query_status'." << std::endl;
						}
					}
					catch (const nlohmann::json::parse_error& e) {
						std::cerr << "JSON Parse Error: " << e.what() << std::endl;
						std::cerr << "Response Content: " << response << std::endl;
					}
					catch (const std::exception& e) {
						std::cerr << "Exception occurred: " << e.what() << std::endl;
					}
				}
				catch (const std::exception& e) {
					std::cerr << "Network Error: Unable to get the hash info. Error: " << e.what() << std::endl;
				}
			}

			BOOL MalwareFlag = LocalDB.find(Filehash) != LocalDB.end();
			BOOL FinFlag = false;
			if (MalwareFlag == true || API_status == true) {
				FinFlag = true;
			}

			nlohmann::json ScanFileinfo = {
				{"File_Path", scanpath},
				{"SHA-256 Hash", Filehash},
				{"Local - Malware Flag", FinFlag ? "Yes" : "No"},
				{"Timestamp",Start_Time}
			};
			scanSummary.push_back(ScanFileinfo);
		}
	}

	nlohmann::json Scancombine;
	Scancombine["Scan info"] = scanSummary;
	Scancombine["System info"] = ScanFileCombine;


	nlohmann::json Malwarecombine;
	Malwarecombine["Malware Detected info"] = MaldecSummary;
	Malwarecombine["System info"] = ScanFileCombine;

	GenerateReport(Scancombine, Malwarecombine);

	std::cout << std::endl;

	std::cout << okay << " Scan completed successfully. Reports generated." << std::endl;
}

std::string Finfo(const std::string& filepath ) { // to take the file directory and file info info 

	if (filepath.empty()) {
		std::cout << " Error: Issue With Path" << std::endl;
	}
	std::string path = filepath;
	// using filesystem to seperate the component of the input
	std::filesystem::path p(path);

	std::string subfolder = p.stem().string();
	std::string mainfolder = p.parent_path().filename().string();
	std::string user = p.parent_path().parent_path().filename().string();
	std::cout << std::endl;

	return info + std::string(" User : ") + user + "\n" + info + " Main folder : " + mainfolder + "\n" + info + " Subfolder : " + subfolder;
}

int main(int argc, char* argv[]) {

			//checking the paramenter
			if (argc < 2) {
				std::cerr << "Unable to find the File Path " << GetLastError() << std::endl;
				return 1;
			}

			const char* filepath = argv[1];
			std::string LocalDB = "full_sha256.txt";
			std::string path = filepath;
			// using filesystem to seperate the component of the input
			std::filesystem::path p(path);
			std::string subfolder = p.stem().string();
			std::string mainfolder = p.parent_path().filename().string();
			std::string user = p.parent_path().parent_path().filename().string();

	
			std::cout << std::endl;
			std::cout << info << " Computing the Hash of the mentioned file : " << filepath << std::endl;

			std::cout << Finfo(filepath) << std::endl;
	//passing the file path to the function to find the hash of the file
			FolderEnum(filepath, LocalDatabase(LocalDB), user);

	return 0;
}