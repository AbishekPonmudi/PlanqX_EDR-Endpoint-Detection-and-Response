# This is written by Havox@ CYberNet #
# @CopyRight under MIT LICENCE #
# Author = "@HaVoX#"
# $+++++++++++++++++++++++++++++++++++++++++++++++++++++++$#

# import os
# import pefile

# # List of suspicious strings for each malware type
# HEURISTIC_STRINGS = {
#     'Trojan_Generic': [
#         b'This program cannot be run in DOS mode',
#         b'maliciousfunction',
#         b'backdoor',
#         b'rat',
#         b'keylogger'
#     ],
#     'Ransomware_Generic': [
#         b'Your files have been encrypted',
#         b'All your files are encrypted',
#         b'Decrypt your files',
#         b'.locked',
#         b'.crypt',
#         b'.enc'
#     ],
#     'Spyware_Generic': [
#         b'CaptureScreenshot',
#         b'KeyLogger',
#         b'StealPassword',
#         b'BrowserHistory'
#     ],
#     'Worm_Generic': [
#         b'SpreadToNetwork',
#         b'CopyToUSB',
#         b'NetworkPropagation',
#         b'EmailSpread'
#     ],
#     'ExploitKit_Generic': [
#         b'Exploit',
#         b'Shellcode',
#         b'ExploitPayload',
#         b'ExploitKit'
#     ],
#     'Packed_Malware_Generic': [
#         b'UPX0',
#         b'MEW',
#         b'FSG',
#         b'PECompact',
#         b'ASPack'
#     ],
#     'KnownMalwareFamily': [
#         b'\xE8\x00\x00\x00\x00\x5D\xC3',
#         b'\x6A\x40\x68\x00\x30\x00\x00',
#         b'\x60\x89\xE5\x31\xC0\x64\x8B\x50\x30',
#         b'\x68\x8D\x4C\x24\x04\x89\xE1\x6A\x10'
#     ],
#     'Obfuscated_Malware_Generic': [
#         b'Function1',
#         b'Function2',
#         b'EncodedPayload',
#         b'ObfuscatedCode',
#         b'\x8B\x45\x0C\x89\x45\xFC\x8B\x45\x10'
#     ],
#     'Polymorphic_Malware_Generic': [
#         b'PolymorphicEngine',
#         b'CodeMutation',
#         b'VariableEncryption'
#     ],
#     'Fileless_Malware_Generic': [
#         b'Powershell',
#         b'Invoke-Mimikatz',
#         b'ReflectiveLoader'
#     ]
# }

# def is_suspicious_file(file_path):
#     try:
#         if not os.access(file_path, os.R_OK):
#             return None  # Skip files that cannot be read

#         pe = pefile.PE(file_path)
        
#         # Check for high entropy sections (indicative of packing)
#         for section in pe.sections:
#             if section.get_entropy() > 7.5:
#                 return 'Packed_Malware_Generic'

#         # Check for suspicious imports
#         if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
#             suspicious_imports = ['LoadLibraryA', 'GetProcAddress', 'VirtualAlloc']
#             for entry in pe.DIRECTORY_ENTRY_IMPORT:
#                 for imp in entry.imports:
#                     if imp.name and imp.name.decode('utf-8', 'ignore') in suspicious_imports:
#                         return 'Trojan_Generic'

#         # Check for unusual section names
#         for section in pe.sections:
#             section_name = section.Name.decode('utf-8', 'ignore').strip()
#             if section_name not in ['.text', '.data', '.rdata']:
#                 return 'Obfuscated_Malware_Generic'

#         # Check for suspicious strings in file content
#         with open(file_path, 'rb') as f:
#             content = f.read()
#             for malware_type, strings in HEURISTIC_STRINGS.items():
#                 if any(s in content for s in strings):
#                     return malware_type

#         return None
    
#     except pefile.PEFormatError:
#         return None
#     except PermissionError:
#         return None  # Skip files that cannot be accessed due to permission errors
#     except Exception as e:
#         print(f"Error processing file {file_path}: {e}")
#         return None

# def scan_files(directory="C:\\"):
#     suspicious_files = {}
#     for root, _, files in os.walk(directory):
#         for file in files:
#             file_path = os.path.join(root, file)
#             try:
#                 result = is_suspicious_file(file_path)
#                 if result:
#                     if file_path not in suspicious_files:
#                         suspicious_files[file_path] = []
#                     suspicious_files[file_path].append(result)
#             except PermissionError:
#                 print(f"Permission denied: {file_path}")  # Log the permission error
#             except Exception as e:
#                 print(f"Error scanning file {file_path}: {e}")  # Log other errors
#     return suspicious_files

# # Example usage
# suspicious_files = scan_files()
# if suspicious_files:
#     print("Malware files found:")
#     for file, types in suspicious_files.items():
#         print(f"{file}")
#         for malware_type in types:
#             print(f"  - {malware_type}")
# else:
#     print("No suspicious files found.")


# import yara
# import os

# def scan_file(file_path, rule_path):
#     try:
#         # Compile the YARA rules
#         rules = yara.compile(filepath=rule_path)
#         # Match the rules against the file
#         matches = rules.match(file_path)
#         if matches:
#             print(f"Malware file found: {file_path}")
#             # matches the files with the YARA rules 
#             for match in matches:
#                 print(f"- Types : {match.rule} , Location : {file_path}")
#         else:
#             print(f"No malware found in: {file_path}")
    
#     except yara.Error as e:
#         print(f"Error scanning {file_path}: {e}")

# file_path = "windows11.exe"
# rule_path = r"rules_yara.yar"

# scan_file(file_path, rule_path)

# if __name__ == "__main__":
#     root = ["C:\\"] if os.name = 'nt' else ['/']



# # YARA WORKING SCRIPT WITH THE INTEGRATION OF THE PEFILE HEADER DETECTION 

# # import os
# # import yara
# # import pefile
# # import logging

# # # Set up logging
# # logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# # # Path to the YARA rules file
# # YARA_RULES_FILE = "rules_yara.yar"

# # # Load YARA rules
# # try:
# #     rules = yara.compile(filepath=YARA_RULES_FILE)
# # except yara.SyntaxError as e:
# #     logging.error(f"YARA syntax error: {e}")
# #     exit(1)

# # def scan_with_yara(file_path):
# #     try:
# #         matches = rules.match(file_path)
# #         return matches
# #     except yara.Error as e:
# #         logging.error(f"YARA error scanning file {file_path}: {e}")
# #         return None

# # def analyze_with_pefile(file_path):
# #     try:
# #         pe = pefile.PE(file_path)

# #         # Check for high entropy sections (indicative of packing)
# #         for section in pe.sections:
# #             if section.get_entropy() > 7.5:
# #                 return "Packed_Malware_Generic"

# #         # Check for suspicious imports
# #         if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
# #             suspicious_imports = ['LoadLibraryA', 'GetProcAddress', 'VirtualAlloc']
# #             for entry in pe.DIRECTORY_ENTRY_IMPORT:
# #                 for imp in entry.imports:
# #                     if imp.name and imp.name.decode('utf-8', 'ignore') in suspicious_imports:
# #                         return "Trojan_Generic"

# #         # Check for unusual section names
# #         for section in pe.sections:
# #             section_name = section.Name.decode('utf-8', 'ignore').strip()
# #             if section_name not in ['.text', '.data', '.rdata']:
# #                 return "Obfuscated_Malware_Generic"

# #         return None
# #     except pefile.PEFormatError:
# #         return None
# #     except PermissionError:
# #         logging.warning(f"Permission denied: {file_path}")
# #         return None
# #     except Exception as e:
# #         logging.error(f"Error analyzing file with pefile {file_path}: {e}")
# #         return None

# # def scan_directory(directory):
# #     suspicious_files = {}
# #     for root, _, files in os.walk(directory):
# #         for file in files:
# #             file_path = os.path.join(root, file)
# #             try:
# #                 yara_matches = scan_with_yara(file_path)
# #                 pefile_analysis = analyze_with_pefile(file_path)

# #                 if yara_matches or pefile_analysis:
# #                     if file_path not in suspicious_files:
# #                         suspicious_files[file_path] = []

# #                     if yara_matches:
# #                         suspicious_files[file_path].extend(str(match) for match in yara_matches)

# #                     if pefile_analysis:
# #                         suspicious_files[file_path].append(pefile_analysis)

# #             except PermissionError:
# #                 logging.warning(f"Permission denied: {file_path}")
# #             except Exception as e:
# #                 logging.error(f"Error scanning file {file_path}: {e}")
# #     return suspicious_files

# # # Example usage
# # if __name__ == "__main__":
# #     directory_to_scan = "C:\\"  # Set the directory you want to scan
# #     logging.info(f"Starting scan in directory: {directory_to_scan}")
# #     suspicious_files = scan_directory(directory_to_scan)
# #     if suspicious_files:
# #         logging.info("Malware files found:")
# #         for file, types in suspicious_files.items():
# #             logging.info(f"{file}")
# #             for malware_type in types:
# #                 logging.info(f"  - {malware_type}")
# #     else:
# #         logging.info("No suspicious files found.")


# # ADDING PE AND YARA WITH EXIXTING SIGNATURE FILE SCANNING AND HASH SCANNING CODE 
# import argparse
# import hashlib
# import os
# import sys
# import logging
# import win32com.shell.shell as shell
# import yara
# import pefile
# from tqdm import tqdm

# def main():
#     # Argument parser setup
#     parser = argparse.ArgumentParser(description="File Scanner")
#     parser.add_argument("scan_type", choices=["normal", "full", "custom"], help="Enter the type of scan")
#     parser.add_argument("--directory", help="Enter the custom location to scan")
#     args = parser.parse_args()

#     # Elevate to admin if not already elevated and scan type is not custom
#     ADMIN = "Isadmin"
#     if args.scan_type != "custom" and sys.argv[-1] != ADMIN:
#         script = os.path.abspath(sys.argv[0])
#         params = ' '.join([script] + sys.argv[1:] + [ADMIN])
#         shell.ShellExecuteEx(lpVerb='runas', lpFile=sys.executable, lpParameters=params)
      

#     # Load YARA rules
#     rules_path = r"hash_rules\Rules_yara.yar"
#     try:
#         rules = yara.compile(filepath=rules_path)
#     except yara.SyntaxError as e:
#         logging.error(f"YARA syntax error: {e}")
#         exit(1)

#     # Load malicious hashes
#     malicious_hashes = load_malicious_hashes()

#     # Define root directories to scan
#     if args.scan_type == "custom" and args.directory:
#         root_dirs = [args.directory]
#     else:
#         root_dirs = ['C:\\'] if os.name == 'nt' else ['/']

#     # Scan directories and gather file paths
#     file_paths = []
#     for root in root_dirs:
#         file_paths.extend(scan_directory(root))
#     total_files = len(file_paths)

#     # Scan files with progress bar
#     malicious_files = []
#     with tqdm(total=total_files, desc="Scanning Files", unit="file") as pbar:
#         for file_path in file_paths:
#             results = []

#             # Scan with hash
#             file_hash = calculate_hash(file_path)
#             if file_hash and file_hash in malicious_hashes:
#                 results.append(f"Hash match: {file_path} - {file_hash}")

#             # Scan with YARA
#             yara_matches = scan_with_yara(file_path, rules)
#             if yara_matches:
#                 for match in yara_matches:
#                     results.append(f"YARA match: {file_path} - {match}")

#             # Scan with PEfile
#             pefile_analysis = analyze_with_pefile(file_path)
#             if pefile_analysis:
#                 results.append(f"PEfile analysis: {file_path} - {pefile_analysis}")

#             if results:
#                 malicious_files.extend(results)

#             pbar.update(1)

#     # Display the results
#     print(f"\nScanning complete. {len(malicious_files)} malicious files detected.")
#     for result in malicious_files:
#         print(result)

#     # Print the paths of detected malicious files
#     if malicious_files:
#         print("\nMalicious file paths:")
#         for result in malicious_files:
#             print(result)


# def load_malicious_hashes(file_path=r"hashes\malicious_hashes.idx"):
#     malicious_hashes = set()
#     try:
#         with open(file_path, mode='r') as f:
#             for line in f:
#                 hash_value = line.split('|')[0].strip()
#                 if hash_value:
#                     malicious_hashes.add(hash_value)
#     except FileNotFoundError:
#         print(f"Database not found in this location {file_path}, Please ensure the file exists.")
#     return malicious_hashes

# def calculate_hash(file_path):
#     sha256 = hashlib.sha256()
#     try:
#         with open(file_path, 'rb') as f:
#             for byte_block in iter(lambda: f.read(4096), b""):
#                 sha256.update(byte_block)
#         return sha256.hexdigest()
#     except (PermissionError, FileNotFoundError, OSError) as e:
#         print(f"Skipping the file {file_path}: {e}")
#         return None

# def scan_with_yara(file_path, rules):
#     try:
#         matches = rules.match(file_path)
#         return matches
#     except yara.Error as e:
#         logging.error(f"YARA error scanning file {file_path}: {e}")
#         return None

# def analyze_with_pefile(file_path):
#     try:
#         pe = pefile.PE(file_path)
#         # Check for high entropy sections (indicative of packing)
#         for section in pe.sections:
#             if section.get_entropy() > 7.5:
#                 return "Packed_Malware_Generic"
#         # Check for suspicious imports
#         if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
#             suspicious_imports = ['LoadLibraryA', 'GetProcAddress', 'VirtualAlloc']
#             for entry in pe.DIRECTORY_ENTRY_IMPORT:
#                 for imp in entry.imports:
#                     if imp.name and imp.name.decode('utf-8', 'ignore') in suspicious_imports:
#                         return "Trojan_Generic"
#         # Check for unusual section names
#         for section in pe.sections:
#             section_name = section.Name.decode('utf-8', 'ignore').strip()
#             if section_name not in ['.text', '.data', '.rdata']:
#                 return "Obfuscated_Malware_Generic"
#         return None
#     except pefile.PEFormatError:
#         return None
#     except PermissionError:
#         logging.warning(f"Permission denied: {file_path}")
#         return None
#     except Exception as e:
#         logging.error(f"Error analyzing file with pefile {file_path}: {e}")
#         return None

# def scan_directory(root):
#     file_paths = []
#     for dirpath, _, filenames in os.walk(root):
#         for file in filenames:
#             file_paths.append(os.path.join(dirpath, file))
#     return file_paths

# if __name__ == "__main__":
#     main()


# EFFICIENCY VERSION CODE USING SIGNATURE MATCHING , PE HEADER AND YARA RULES
import argparse
import hashlib
import os
import sys
import logging
import time
import yara
import pefile
from win32comext.shell import shell
from tqdm import tqdm

def main():
    # Argument parser setup
    parser = argparse.ArgumentParser(description="File Scanner")
    parser.add_argument("scan_type", choices=["normal", "full", "custom"], help="--> Mention the specific Mode")
    parser.add_argument("--directory", help="Please! Declare --directory and <Folder path>")
    args = parser.parse_args()

    # Elevate to admin if not already elevated and scan type is not custom
    ADMIN = "Isadmin"
    if args.scan_type != "custom" and sys.argv[-1] != ADMIN:
        script = os.path.abspath(sys.argv[0])
        params = ' '.join([script] + sys.argv[1:] + [ADMIN])
        shell.ShellExecuteEx(lpVerb='runas', lpFile=sys.executable, lpParameters=params)
        
    # Start timing the scan
    start_time = time.time()

    # Load YARA rules
    rules_path = r"hash_rules\Rules_yara.yar"
    try:
        rules = yara.compile(filepath=rules_path)
    except yara.SyntaxError as e:
        logging.error(f"Rules syntax error: {e}")
        exit(1)

    # Load malicious hashes
    malicious_hashes = load_malicious_hashes()

    # Define root directories to scan
    if args.scan_type == "custom" and args.directory:
        root_dirs = [args.directory]
    else:
        root_dirs = ['C:\\'] if os.name == 'nt' else ['/']

    # Scan directories and gather file paths
    file_paths = []
    for root in root_dirs:
        file_paths.extend(scan_directory(root))
    total_files = len(file_paths)

    # Show the progress bar according to the file scanning percentage
    malicious_files = []
    with tqdm(total=total_files, desc="Scanning Files", unit="file") as pbar:
        for file_path in file_paths:
            results = []

            # Scan the files with hash
            file_hash = calculate_hash(file_path)
            if file_hash and file_hash in malicious_hashes:
                results.append(f"File : {file_path} - {file_hash}")

            # Scan the files with YARA
            yara_matches = scan_with_yara(file_path, rules)
            if yara_matches:
                for match in yara_matches:
                    results.append(f"File : {file_path} - {match}")

            # Scan the files with PEfile
            pefile_analysis = analyze_with_pefile(file_path)
            if pefile_analysis:
                results.append(f"File : {file_path} - {pefile_analysis}")

            if results:
                malicious_files.extend(results)

            pbar.update(1)

# Calculate the elapsed time and displaying the result
    elapsed_time = time.time() - start_time
    elapsed_time_str = time.strftime("%H:%M:%S", time.gmtime(elapsed_time))

    print(f"\nScanning complete. {len(malicious_files)} malicious files detected.")
    print(f"Current Scanning Time: {elapsed_time_str}")
    print(f"Completed {args.scan_type} on : {file_path}")
    print(f"Scanned Mode: {args.scan_type}")
    if malicious_files:
        print("\nMalicious file paths:")
        for result in malicious_files:
            print(result)

# storing the output in the log file 
    log_file = "Scan_log.txt"
    with open(log_file,"w") as f:
        f.write(f"scanning complete, {len(malicious_files)} malicious files detected\n")
        f.write(f"current scanning time: {elapsed_time_str}\n")
        f.write(f"Completed {args.scan_type} on {file_path}\n")
        f.write(f"Scanned mode: {args.scan_type}\n")
        if malicious_files:
            print("\nMalicious file path:\n")
            for result in malicious_files:
                f.write(result + "\n")

def load_malicious_hashes(file_path=r"hashes\full-md5_hashes.txt"):
    malicious_hashes = set()
    try:
        with open(file_path, mode='r') as f:
            for line in f:
                hash_value = line.split('|')[0].strip()
                if hash_value:
                    malicious_hashes.add(hash_value)
    except FileNotFoundError:
        print(f"Database not found in this location {file_path}, Please ensure the file exists.")
    return malicious_hashes

# convert the files to hash
def calculate_hash(file_path):
    sha256 = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256.update(byte_block)
        return sha256.hexdigest()
    except (PermissionError, FileNotFoundError, OSError) as e:
        print(f"Skipping the System files : {file_path}: {e}")
        return None
# For yara analysis
def scan_with_yara(file_path, rules):
    try:
        matches = rules.match(file_path)
        return matches
    except yara.Error as e:
        logging.error(f"System File Error code 2 {file_path}: {e}")
        return None
# for pe analysis
def analyze_with_pefile(file_path):
    try:
        pe = pefile.PE(file_path)
        # Check for high entropy sections (indicative of packing)
        for section in pe.sections:
            if section.get_entropy() > 7.5:
                return "Packed_Malware_Generic"
        # Check for suspicious imports
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            suspicious_imports = ['LoadLibraryA', 'GetProcAddress', 'VirtualAlloc', 'CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory']
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name and imp.name.decode('utf-8', 'ignore') in suspicious_imports:
                        return f"Suspicious API: {imp.name.decode('utf-8', 'ignore')}"
        # Check for unusual section names
        for section in pe.sections:
            section_name = section.Name.decode('utf-8', 'ignore').strip()
            if section_name not in ['.text', '.data', '.rdata']:
                return "Obfuscated_Malware_Generic"
        return None
    except pefile.PEFormatError:
        return None
    except PermissionError:
        logging.warning(f"Permission denied: {file_path}")
        return None
    except Exception as e:
        logging.error(f"System Files >>  {file_path}: {e}")
        return None
# for scanning from the root directory applicable for full , normal mode 
def scan_directory(root):
    file_paths = []
    for dirpath, _, filenames in os.walk(root):
        for file in filenames:
            file_paths.append(os.path.join(dirpath, file))
    return file_paths

if __name__ == "__main__":
    main()
