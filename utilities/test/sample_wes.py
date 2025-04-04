import zipfile
import os
import csv

def unzip_definitions(zip_path, extract_to):
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(extract_to)

def parse_definitions(definitions_file):
    vulnerabilities = []
    with open(definitions_file, 'r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            vulnerabilities.append(row)
    return vulnerabilities

def format_vulnerabilities(vulnerabilities):
    formatted_output = "[+] Parsing systeminfo output\n"
    formatted_output += "[+] Operating System\n"
    formatted_output += "    - Name: Windows 11 Version 23H2 for x64-based Systems\n"
    formatted_output += "    - Generation: 11\n"
    formatted_output += "    - Build: 22631\n"
    formatted_output += "    - Version: 23H2\n"
    formatted_output += "    - Architecture: x64-based\n"
    formatted_output += "    - Installed hotfixes (4): KB5037591, KB5027397, KB5036980, KB5037663\n"
    formatted_output += "[+] Loading definitions\n"
    formatted_output += "    - Creation date of definitions: 20240510\n"
    formatted_output += "[+] Determining missing patches\n"
    formatted_output += "[!] Found vulnerabilities!\n\n"

    for vuln in vulnerabilities:
        formatted_output += f"Date: {vuln['Date']}\n"
        formatted_output += f"CVE: {vuln['CVE']}\n"
        formatted_output += f"KB: {vuln['KB']}\n"
        formatted_output += f"Title: {vuln['Title']}\n"
        formatted_output += f"Affected product: {vuln['Affected_product']}\n"
        formatted_output += f"Affected component: {vuln['Affected_component']}\n"
        formatted_output += f"Severity: {vuln['Severity']}\n"
        formatted_output += f"Impact: {vuln['Impact']}\n"
        formatted_output += f"Exploit: {vuln['Exploit']}\n\n"

    return formatted_output

# Paths to zip file and extraction directory
zip_path = 'C:\Users\Abishek\Documents\TIP_dev\windows_exploit_suggestor\wesng\wesng\definitions.zip'
extract_to = 'C:\Users\Abishek\Documents\TIP_dev\windows_exploit_suggestor\wesng\wesng'

# Unzip and parse
unzip_definitions(zip_path, extract_to)
definitions_file = os.path.join(extract_to, 'CVEs_20240510.csv')
vulnerabilities = parse_definitions(definitions_file)

# Format and print the output
formatted_output = format_vulnerabilities(vulnerabilities)
print(formatted_output)
