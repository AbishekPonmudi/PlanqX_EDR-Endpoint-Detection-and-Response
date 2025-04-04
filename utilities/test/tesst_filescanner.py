# This is written by Havox@ CYberNet #
# @CopyRight under MIT LICENCE #
# Author = "@HaVoX#"
# $+++++++++++++++++++++++++++++++++++++++++++++++++++++++$#

import hashlib
import os
import requests
import win32com.shell.shell as shell
import sys
from tqdm import tqdm

# Set this code to run as admin
ADMIN = "adadmin"
if sys.argv[-1] != ADMIN:
    script = os.path.abspath(sys.argv[0])
    params = ' '.join([script] + sys.argv[1:] + [ADMIN])
    shell.ShellExecuteEx(lpVerb='runas', lpFile=sys.executable, lpParameters=params)
    sys.exit(0)  # Ensure the script exits after re-launching as admin

# Include VirusTotal API key for the online HTTP-based file scanning
api = "2942ff8c354be745ff55e6ef69310800379a0abe2b6ae6b9de2baffa577b7388"

# Calculate the hash of the file in the system with the root files
def cal_hash(file_path):
    sha256 = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            for byte in iter(lambda: f.read(4096), b""):
                sha256.update(byte)
        return sha256.hexdigest()
    except (PermissionError, FileNotFoundError) as e:
        print(f"Skipping the file {file_path}: {e}")
        return None

# This will check file signature hash with the VirusTotal API
def query(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        'x-apikey': api
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        return f"Error at VirusTotal with the hash {file_hash}: {response.status_code}"

# Scan the files
def scan_file(file_path):
    file_hash = cal_hash(file_path)
    if file_hash:
        result = query(file_hash)
        if isinstance(result, dict) and 'data' in result:
            if result['data']['attributes']['last_analysis_stats']['malicious'] > 0:
                return f"Malicious content detected! File location: {file_path}, File hash: {file_hash}"
    return None

# Scan the root directory for the malicious content with file path and hash values from the table or API
def scan_directory(root):
    file_paths = []
    for dirpath, _, filenames in os.walk(root):
        for file in filenames:
            file_paths.append(os.path.join(dirpath, file))
    return file_paths

# Function declared to scan the entire file on the OS. If in nt, get to root directory using '\'
if __name__ == "__main__":
    root_dir = ['C:\\'] if os.name == 'nt' else ['/']
    total_files = 0
    malicious_count = 0

    # Gather all file paths
    file_paths = []
    for root in root_dir:
        file_paths.extend(scan_directory(root))
    total_files = len(file_paths)

    # Scan files with progress bar
    with tqdm(total=total_files, desc="Scanning Files", unit="file") as pbar:
        for file_path in file_paths:
            result = scan_file(file_path)
            if result:
                print(result)
                malicious_count += 1
            pbar.update(1)

    print(f"\nScanning complete. {malicious_count} malicious files detected.")
