# Written By Haovx Server - side code -> Server CLI Panel
import sys
import os
import subprocess
import json
import getpass
import hmac
import hashlib
import time
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime


try:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    pyhton_dir = os.path.abspath(os.path.join(script_dir, "NetMon_Files", "Pyhton"))
    sys.path.append(pyhton_dir)

    # from net_src.Running_services.Network_service_cap import *
    # from wesng import *
    # from sys_src.Sys_scan import *
    # from sys_src.main import *
except ImportError as e:
    print(f"[!] Warning: Missing module - {e}")

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    BLACK = '\033[30m'
    RED = '\033[31m'
    YELLOW = '\033[33m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_WHITE = '\033[47m'
    GRAY = '\033[90m'

@dataclass
class Service:
    name: str
    description: str
    options: List[str]

AUTH_FILE = 'auth.json'
SERVICES = [
    Service("Forwarder Configuration", "Manage log forwarding settings", ["Setup Forwarder", "View Configuration", "Test Connection"]),
    Service("Network Configuration", "Configure network monitoring and policies", [
        "Trigger Traffic Agent", "View Live Traffic", "Reboot Server", "Check Client Status",
        "View Client Connections", "Display Custom Policies", "Manage Policies"
    ]),
    Service("Rules & Policies", "Create and manage security rules", ["Create Rule", "Edit Rule", "Delete Rule", "List Rules"]),
    Service("Custom Blocking", "Configure custom block lists", ["Add Block", "Remove Block", "View Blocks"]),
    Service("Network IP Scanner", "Scan network for IP addresses", ["Initiate Scan", "View Results", "Export Data"]),
    Service("Alerts & Warnings", "Manage alert configurations", ["View Alerts", "Configure Alerts", "Test Alert"]),
    Service("Patch Management", "Handle client patch deployment", ["Check Updates", "Deploy Patch", "Patch Status"]),
    Service("Management Server", "Control the management server", ["Start Server", "Stop Server", "Server Status"]),
    Service("Connection Status", "Monitor client connections", ["List Connections", "Refresh Status", "Disconnect Client"]),
    Service("Client Information", "View and manage client details", ["View Details", "Update Info", "Export Data"]),
    Service("Email Database", "Manage client email IDs", ["Add Email", "Remove Email", "View Database"]),
    Service("Vulnerability Status", "Assess client vulnerabilities", ["Scan Client", "View Report", "Remediate"]),
    Service("Report Generator", "Generate and download reports", ["Generate Report", "Download PDF", "Email Report"]),
    Service("Live Traffic Monitor", "Monitor network traffic in real-time", ["Start Monitoring", "Stop Monitoring", "View Logs"]),
    Service("Malware Scanner", "Scan for malware and threats", [
        "Run Full Scan", "Generate Report", "Set Rules Preset", "Edit Yara Rules",
        "Import Libraries", "Configure Hooking", "Tune Scanner", "Schedule Scan"
    ]),
    Service("System Vulnerabilities", "Check system vulnerabilities", ["Run Vulnerability Scan", "View Report", "Export Results"]),
    Service("Threat Hunting", "Perform proactive threat hunting", ["Start Hunt", "View Findings", "Save Session"]),
    Service("Activity Reporter", "Generate activity reports", ["Create Report", "Customize Layout", "Export Report"]),
    Service("Activity Monitor", "Monitor endpoint activities", ["Start Monitoring", "View Logs", "Set Alerts"]),
    Service("Endpoint Isolation", "Isolate compromised endpoints", ["Isolate Now", "Revert Isolation", "Check Status"])
]

def print_banner() -> None:
    """Display a professional and readable EDR banner."""
    time.sleep(1)
    print(f"{Colors.GRAY}[*] Initializing Planqx EDR components...{Colors.ENDC}")
    time.sleep(1)
    banner = f"""
{Colors.BOLD}{Colors.CYAN}=================================================================================
          Planqx EDR - Advanced Endpoint Detection and Response
================================================================================={Colors.ENDC}
{Colors.BLUE}
                                                    
 ███████████  ████                                 █████ █████       ██████████ ██████████   ███████████  
░░███░░░░░███░░███                                ░░███ ░░███       ░░███░░░░░█░░███░░░░███ ░░███░░░░░███ 
 ░███    ░███ ░███   ██████   ████████    ████████ ░░███ ███         ░███  █ ░  ░███   ░░███ ░███    ░███ 
 ░██████████  ░███  ░░░░░███ ░░███░░███  ███░░███   ░░█████          ░██████    ░███    ░███ ░██████████  
 ░███░░░░░░   ░███   ███████  ░███ ░███ ░███ ░███    ███░███         ░███░░█    ░███    ░███ ░███░░░░░███ 
 ░███         ░███  ███░░███  ░███ ░███ ░███ ░███   ███ ░░███        ░███ ░   █ ░███    ███  ░███    ░███ 
 █████        █████░░████████ ████ █████░░███████  █████ █████       ██████████ ██████████   █████   █████
░░░░░        ░░░░░  ░░░░░░░░ ░░░░ ░░░░░  ░░░░░███ ░░░░░ ░░░░░       ░░░░░░░░░░ ░░░░░░░░░░   ░░░░░   ░░░░░  
                                             ░███                                                         
                                             █████                                                        
                                            ░░░░░            
    
    
    
{Colors.ENDC}{Colors.YELLOW}    Planqx Inc. © 2025 - All Rights Reserved{Colors.ENDC}
{Colors.BOLD}{Colors.CYAN}================================================================================={Colors.ENDC}
    """
    print(banner)

def load_credentials() -> Dict[str, str]:
    """Load authentication credentials securely."""
    try:
        if os.path.exists(AUTH_FILE):
            with open(AUTH_FILE, 'r') as file:
                return json.load(file)
        return {}
    except (json.JSONDecodeError, IOError) as e:
        print(f"{Colors.FAIL}[!] Error loading credentials: {e}{Colors.ENDC}")
        return {}

def save_credentials(username: str, password_hmac: str) -> None:
    """Save encrypted credentials to file."""
    try:
        credentials = {'username': username, 'password': password_hmac}
        with open(AUTH_FILE, 'w') as file:
            json.dump(credentials, file)
    except IOError as e:
        print(f"{Colors.FAIL}[!] Error saving credentials: {e}{Colors.ENDC}")

def generate_hmac(message: str, key: bytes) -> str:
    """Generate HMAC-SHA256 hash for secure authentication."""
    return hmac.new(key, message.encode(), hashlib.sha256).hexdigest()

def get_password_input() -> Tuple[str, str]:
    """Securely retrieve password input from user."""
    password = getpass.getpass(f"{Colors.GRAY}[*] Enter New Password: {Colors.ENDC}")
    re_password = getpass.getpass(f"{Colors.GRAY}[*] Re-Enter Password: {Colors.ENDC}")
    return password, re_password

def authenticate() -> Optional[str]:
    """Handle user authentication."""
    auth = load_credentials()

    if not auth or 'username' not in auth or 'password' not in auth:
        print(f"{Colors.GREEN}[+] Initial Setup Required{Colors.ENDC}")
        username = input(f"{Colors.GRAY}[*] Enter New Username: {Colors.ENDC}")
        while True:
            password, re_password = get_password_input()
            if password != re_password:
                print(f"{Colors.FAIL}[!] Passwords do not match.{Colors.ENDC}")
                continue
            key = username.encode()
            user_hmac = generate_hmac(username, key)
            pass_hmac = generate_hmac(password, key)
            save_credentials(user_hmac, pass_hmac)
            print(f"{Colors.GREEN}[+] Setup complete. Please login.{Colors.ENDC}")
            return None

    print(f"{Colors.CYAN}=== Planqx EDR Login ==={Colors.ENDC}")
    username = input(f"{Colors.GRAY}[*] Username: {Colors.ENDC}")
    key = username.encode()
    password = getpass.getpass(f"{Colors.GRAY}[*] Password: {Colors.ENDC}")
    user_hmac = generate_hmac(username, key)
    pass_hmac = generate_hmac(password, key)

    if user_hmac == auth['username'] and pass_hmac == auth['password']:
        print(f"{Colors.GREEN}[+] Login successful.{Colors.ENDC}")
        return username
    print(f"{Colors.FAIL}[!] Login failed.{Colors.ENDC}")
    exit(1)

def display_services() -> None:
    """Display available services inline."""
    print(f"{Colors.BG_YELLOW}{Colors.BLACK}=== Planqx EDR Services ==={Colors.ENDC}")
    for i, service in enumerate(SERVICES, 1):
        print(f"{Colors.BLUE}{Colors.BOLD}  [{i}] {service.name}{Colors.ENDC} ---> {Colors.GRAY}{service.description}{Colors.ENDC}")

def display_help() -> None:
    """Display CLI help."""
    print(f"{Colors.YELLOW}=== Planqx EDR Commands ==={Colors.ENDC}")
    print(f"  hello/options  - List services")
    print(f"  use <number>   - Select a service")
    print(f"  show           - Show service options")
    print(f"  select <number>- Run an option")
    print(f"  back           - Return to root")
    print(f"  clear          - Clear screen")
    print(f"  exit           - Log out")

def clear_screen() -> None:
    """Clear the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

def execute_option(service_name: str, option_index: int) -> None:
    """Execute selected option with main features integrated."""
    print(f"{Colors.CYAN}[*] Executing {service_name} - {SERVICES[next(i for i, s in enumerate(SERVICES) if s.name == service_name)].options[option_index]}{Colors.ENDC}")

    # Main Features with If Conditions
    if service_name == "Network Configuration":
        if option_index == 0:  # Trigger Traffic Agent
            print(f"{Colors.GRAY}    Starting traffic agent...{Colors.ENDC}")
            try:
                python_executable = sys.executable
                command = (
                    f'Start-Process PowerShell -ArgumentList \'-NoExit\', \'-Command\', '
                    f'\'"{python_executable} -c \\"from NetMon_Files.PY-Version v1.0.1.Main_server.py import start_mitmproxy; start_mitmproxy();response();request() \\""\''
                )
                subprocess.run(["powershell", "-Command", command], check=True)
                print(f"{Colors.GREEN}    [+] Traffic agent started.{Colors.ENDC}")
            except subprocess.SubprocessError as e:
                print(f"{Colors.FAIL}    [!] Failed: {e}{Colors.ENDC}")
        elif option_index == 1:  # View Live Traffic
            print(f"{Colors.GRAY}    Viewing live traffic...{Colors.ENDC}")
            # Placeholder for future implementation
        elif option_index == 2:  # Reboot Server
            print(f"{Colors.GRAY}    Rebooting server...{Colors.ENDC}")
            # Add reboot logic here later
            
            # #
            # 
            # 
            # 
            # 
            # 
            # #
        # Add more options using elif condition 

    elif service_name == "Malware Scanner":
        if option_index == 0:  # Run Full Scan
            print(f"{Colors.GRAY}    Initiating malware scan...{Colors.ENDC}")
            try:
                work_dir = os.path.join(os.getcwd(), "sys_src")
                subprocess.Popen(
                    ["start", "cmd", "/k", "python", "Sys_scan.py", "normal"],
                    shell=True,
                    cwd=work_dir
                )
                print(f"{Colors.GREEN}    [+] Scan initiated.{Colors.ENDC}")
            except Exception as e:
                print(f"{Colors.FAIL}    [!] Error: {e}{Colors.ENDC}")
        elif option_index == 1:  # Generate Report
            print(f"{Colors.GRAY}    Generating scan report...{Colors.ENDC}")
            
        elif option_index == 5:
            print(f"{Colors.RED}\nlooking for Suspicioud API Call On CLient Connected.... {Colors.ENDC}\n")
            
            exec_path = r"C:\Users\Abishek\Documents\Maldev\NtCreateUserProcess\x64\Debug\API-Mon_EDR_Modules.exe"
            
            try:
                subprocess.Popen(exec_path, shell=True)
                print(f"{Colors.GREEN}    [+] Monitoring started successfully.{Colors.ENDC}\n")
                print(f"{Colors.CYAN} \nPress Enter,To go back Server Panel...\n {Colors.ENDC}")
            except Exception as e:
                print(f"{Colors.FAIL}    [!] Error: {e}{Colors.ENDC}")
                
            
            # #
            # 
            # 
            # 
            # 
            # 
            # #
        # Add more options  using elif condition

    # Placeholder for future services
    
    else:
        print(f"{Colors.YELLOW}    [*] '{service_name}' option {option_index + 1} not yet implemented.{Colors.ENDC}")
        print(f"{Colors.GRAY}    Add functionality in execute_option() under '{service_name}' condition.{Colors.ENDC}")

def custom_cli_shell(username: str) -> None:
    """Run the CLI shell with simplified navigation."""
    current_path = [f"{username}@Planqx-EDR"]
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"{Colors.GREEN}[+] Session Started: {timestamp}{Colors.ENDC}")
    print(f"{Colors.CYAN}    Welcome to Planqx EDR{Colors.ENDC}")

    while True:
        prompt = "/".join(current_path)
        command = input(f"{Colors.GRAY}[{prompt}]# {Colors.ENDC}").strip().lower()

        if command == 'clear':
            clear_screen()
            continue

        if command in ['hello', 'options']:
            display_services()
            continue

        if command == 'help':
            display_help()
            continue

        if command.startswith('use '):
            try:
                choice = int(command.split()[1]) - 1
                if 0 <= choice < len(SERVICES):
                    current_path = [f"{username}@Planqx-EDR", SERVICES[choice].name]
                    print(f"{Colors.GREEN}[+] Selected: {SERVICES[choice].name}{Colors.ENDC}")
                else:
                    print(f"{Colors.WARNING}[!] Invalid service number.{Colors.ENDC}")
            except (ValueError, IndexError):
                print(f"{Colors.WARNING}[!] Usage: 'use <number>'{Colors.ENDC}")
            continue

        if command == 'show':
            if len(current_path) > 1:
                service_name = current_path[-1]
                service = next((s for s in SERVICES if s.name == service_name), None)
                if service:
                    print(f"{Colors.BG_GREEN}{Colors.BLACK}=== {service_name} Options ==={Colors.ENDC}")
                    for i, option in enumerate(service.options, 1):
                        print(f"{Colors.BLUE}{Colors.BOLD}  {i}. {option}{Colors.ENDC}")
                else:
                    print(f"{Colors.WARNING}[!] Service not found.{Colors.ENDC}")
            else:
                print(f"{Colors.YELLOW}[*] Use 'hello' to list services.{Colors.ENDC}")
            continue

        if command.startswith('select '):
            if len(current_path) <= 1:
                print(f"{Colors.WARNING}[!] Use a service first with 'use'.{Colors.ENDC}")
                continue
            try:
                choice = int(command.split()[1]) - 1
                service_name = current_path[-1]
                service = next((s for s in SERVICES if s.name == service_name), None)
                if service and 0 <= choice < len(service.options):
                    execute_option(service_name, choice)
                else:
                    print(f"{Colors.WARNING}[!] Invalid option.{Colors.ENDC}")
            except (ValueError, IndexError):
                print(f"{Colors.WARNING}[!] Usage: 'select <number>'{Colors.ENDC}")
            continue

        if command == 'back':
            if len(current_path) > 1:
                current_path = [f"{username}@Planqx-EDR"]
                print(f"{Colors.GREEN}[+] Back to root.{Colors.ENDC}")
            else:
                print(f"{Colors.WARNING}[!] Already at root.{Colors.ENDC}")
            continue

        if command == 'exit':
            if confirm_exit(username):
                break
            continue

        print(f"{Colors.WARNING}[!] Invalid command. Try 'help'.{Colors.ENDC}")

def confirm_exit(username: str) -> bool:
    """Confirm exit with password verification."""
    auth = load_credentials()
    print(f"{Colors.YELLOW}[*] Exit requested.{Colors.ENDC}")
    password = getpass.getpass(f"{Colors.GRAY}[*] Enter password: {Colors.ENDC}")
    key = username.encode()
    pass_hmac = generate_hmac(password, key)
    if pass_hmac == auth['password']:
        print(f"{Colors.GREEN}[+] Exiting Planqx EDR.{Colors.ENDC}")
        try:
            disable_proxy()
        except NameError:
            pass 
        return True
    print(f"{Colors.FAIL}[!] Wrong password.{Colors.ENDC}")
    return False

def run_client() -> None:
    """Main entry point."""
    print(f"{Colors.CYAN}[*] Starting Planqx EDR...{Colors.ENDC}")
    print_banner()
    username = authenticate()
    if username:
        custom_cli_shell(username)
    time.sleep(1)

if __name__ == "__main__":
    try:
        run_client()
    except KeyboardInterrupt:
        print(f"{Colors.WARNING}[!] Interrupted by user.{Colors.ENDC}")
        exit(0)
    except Exception as e:
        print(f"{Colors.FAIL}[!] Error: {e}{Colors.ENDC}")
        exit(1)
