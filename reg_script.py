import winreg
import os
import time
import firebase_admin
from firebase_admin import credentials, db

# Output folder and file for local data storage
OUTPUT_FOLDER = "forensic_output"
OUTPUT_FILE = os.path.join(OUTPUT_FOLDER, "forensic_registry_data.txt")

# Ensure the output directory exists
if not os.path.exists(OUTPUT_FOLDER):
    os.makedirs(OUTPUT_FOLDER)

# Firebase initialization
def init_firebase():
    """Initialize Firebase connection using service account credentials."""
    cred = credentials.Certificate('path_to_your_firebase_admin_sdk_json_file.json')
    firebase_admin.initialize_app(cred, {
        'databaseURL': 'https://your-project-id.firebaseio.com/'
    })

# Function to write data locally
def write_to_file(data):
    """Write the collected data to the output file in a readable format."""
    with open(OUTPUT_FILE, 'a') as f:
        f.write(data + "\n")

# Function to upload data to Firebase
def upload_to_firebase(data, path):
    """Upload collected data to Firebase Realtime Database."""
    try:
        ref = db.reference(path)
        ref.push(data)
        print(f"[+] Successfully uploaded data to Firebase at {path}")
    except Exception as e:
        print(f"[-] Failed to upload data to Firebase: {str(e)}")

# Function to read from the Windows Registry
def read_registry(key, sub_key, description, firebase_path):
    """Fetch and return all values from a given registry key with description."""
    try:
        registry_key = winreg.OpenKey(key, sub_key, 0, winreg.KEY_READ)
        i = 0
        data = {"description": description, "sub_key": sub_key, "values": []}
        write_to_file(f"\n[+] {description}")
        while True:
            try:
                value = winreg.EnumValue(registry_key, i)
                value_name, value_data, value_type = value
                result = f"{sub_key} - {value_name}: {value_data} (Type: {value_type})"
                write_to_file(result)
                data["values"].append({value_name: value_data})
                i += 1
            except OSError:
                break
        winreg.CloseKey(registry_key)
        upload_to_firebase(data, firebase_path)
    except FileNotFoundError:
        write_to_file(f"[-] Registry key {sub_key} not found.")
    except Exception as e:
        write_to_file(f"[-] Error accessing registry: {str(e)}")

# Function to collect system information
def collect_system_info():
    """Collect basic system information from the registry."""
    write_to_file("\n[Collecting System Information]")
    read_registry(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "OS Version", "/system_info/os_version")
    read_registry(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName", "Computer Name", "/system_info/computer_name")
    read_registry(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\TimeZoneInformation", "Time Zone Information", "/system_info/time_zone")

# Function to collect network information
def collect_network_info():
    """Collect network configuration from the registry."""
    write_to_file("\n[Collecting Network Information]")
    read_registry(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces", "Network Interfaces", "/network_info/interfaces")

# Function to collect autostart programs
def collect_autostart_programs():
    """Collect programs set to run at startup."""
    write_to_file("\n[Collecting Autostart Programs]")
    read_registry(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "Startup Programs", "/startup_programs/current_user")
    read_registry(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "RunOnce Programs", "/startup_programs/current_user_run_once")
    read_registry(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "Global RunOnce Programs", "/startup_programs/global_run_once")

# Function to collect recent files
def collect_recent_files():
    """Collect recently accessed documents from the registry."""
    write_to_file("\n[Collecting Recent Documents]")
    read_registry(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs", "Recent Files", "/recent_files")

# Function to collect USB devices
def collect_usb_devices():
    """Collect USB device connection information."""
    write_to_file("\n[Collecting USB Device Information]")
    read_registry(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Enum\USBSTOR", "Connected USB Devices", "/usb_devices")
    read_registry(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows Portable Devices\Devices", "USB Device Volume Names", "/usb_device_volume_names")

# Background data collection loop
def background_forensic_collection():
    """Run the forensic data collection in the background."""
    init_firebase()  # Initialize Firebase connection
    while True:
        write_to_file("\n\n=== Forensic Data Collection - New Run ===")
        collect_system_info()
        collect_network_info()
        collect_autostart_programs()
        collect_recent_files()
        collect_usb_devices()

        write_to_file("\n\n=== Data Collection Completed ===")
        # Run every 6 hours (21600 seconds)
        time.sleep(21600)

# Start the forensic data collection
if __name__ == "__main__":
    write_to_file("=== Forensic Registry Data Collection Started ===")
    background_forensic_collection()
