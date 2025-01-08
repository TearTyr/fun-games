import os
import shutil
from tkinter.filedialog import askdirectory
from configparser import ConfigParser
import subprocess
import time
import ctypes
from typing import TypedDict, Optional, Tuple, List
import sys
import psutil
import logging
import argparse
import win32security
import ntsecuritycon as con
import tkinter as tk
from tkinter import filedialog
import pywintypes
import msvcrt
import threading
import atexit

# --- Constants ---
LOG_FILE = "fun_launcher.log"
CONFIG_FILE = "config.ini"
DEFAULT_LOGS_FOLDER = r"C:\Program Files\Wuthering Waves\Wuthering Waves Game\Client\Saved\Logs"
USERS_GROUP = "Users"
WW_OS_PAK = "CenSerPatch-OS.dll"
WW_CN_PAK = "CenSerPatch-CN.dll"
FILTER_FILES_DELETED = [
    "config.json",
    "libraries.txt",
    "winhttp.dll",
]
MENU_OPTIONS = [
    "Launch Game",
    "Enable Log Blocker (Deny Write Permissions)",
    "Disable Log Blocker (Allow Write Permissions)",
    "Change Logs Path",
    "Exit",
    "Cleanup"
]

# --- Logging Setup ---
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("Fun-Launcher")

# --- Configuration ---
config = ConfigParser()

# --- Type Definitions ---
class LoadConfigTyped(TypedDict):
    game_paks_directory: str
    mod_directory: str
    game_executable_path: str
    bypass_sig_dir: str
    loader_dir: str
    binaries_dir: str
    game_dir: str
    debug_dir: str
    debug_mode: str
    version: str
    dx11: str
    logs_folder: str
    logs_blocked: str

# --- Utility Functions ---
def hide_console():
    hwnd = ctypes.windll.kernel32.GetConsoleWindow()
    if hwnd:
        ctypes.windll.user32.ShowWindow(hwnd, 0)

def clear_console():
    os.system("cls" if os.name == "nt" else "clear")

def show_console():
    hwnd = ctypes.windll.kernel32.GetConsoleWindow()
    if hwnd:
        ctypes.windll.user32.ShowWindow(hwnd, 5)

def is_process_running(process_name: str) -> bool:
    for proc in psutil.process_iter(["name"]):
        try:
            if proc.info["name"] == process_name:
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return False

def resource_path(relative_path: str) -> str:
    try:
        base_path = sys._MEIPASS
    except AttributeError:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

# --- Configuration Management ---
def create_default_config():
    if not os.path.exists(CONFIG_FILE):
        config["CONFIG"] = {
            "game_paks_directory": "",
            "game_executable_path": "",
            "binaries_dir": "",
            "game_dir": "",
            "loader_dir": "./pak/loader/~mods",
            "bypass_sig_dir": "./pak/bypass",
            "debug_dir": "./pak/debug",
            "mod_directory": "./pak/Mod",
            "debug_mode": "false",
            "version": "",
            "dx11": "true",
            "logs_folder": DEFAULT_LOGS_FOLDER,
            "logs_blocked": "false",
        }
        with open(CONFIG_FILE, "w") as f:
            config.write(f)
        logger.info("config.ini created with default settings.")

def is_valid_game_directory(path: str) -> bool:
    required_files = ["Client-Win64-Shipping.exe"]
    return all(os.path.exists(os.path.join(path, "Client", "Binaries", "Win64", file)) for file in required_files)

def save_game_directory():
    path = askdirectory(title="Select Wuthering Waves Game Folder")
    if path:
        if not is_valid_game_directory(path):
            print("Invalid game directory selected. Please choose a valid directory.")
            logger.error("Invalid game directory selected.")
            return
        config.read(CONFIG_FILE)
        game_paks_path = os.path.join(path, "Client", "Content", "Paks")
        game_exe_path = os.path.join(path, "Client", "Binaries", "Win64")
        binaries_path = os.path.join(path, "Client", "Binaries", "Win64")
        game_dir = os.path.join(path)
        config["CONFIG"]["game_paks_directory"] = game_paks_path
        config["CONFIG"]["game_executable_path"] = game_exe_path
        config["CONFIG"]["binaries_dir"] = binaries_path
        config["CONFIG"]["game_dir"] = game_dir
        config["CONFIG"]["logs_folder"] = DEFAULT_LOGS_FOLDER
        with open(CONFIG_FILE, "w") as f:
            config.write(f)
        logger.info(f"Game directory saved: {path}")

def load_config() -> LoadConfigTyped:
    create_default_config()
    config.read(CONFIG_FILE)

    if not config.has_section("CONFIG"):
        logger.warning("CONFIG section is missing, creating default config.")
        create_default_config()
        config.read(CONFIG_FILE)

    if not config.has_option("CONFIG", "game_paks_directory") or not config.get("CONFIG", "game_paks_directory") or not is_valid_game_directory(config.get("CONFIG", "game_dir")):
        logger.warning("Wuthering Waves game directory not found or invalid, prompting user to select.")
        save_game_directory()
        config.read(CONFIG_FILE)

    if not config.has_option("CONFIG", "version") or not config.get("CONFIG", "version"):
        set_game_version()
        config.read(CONFIG_FILE)

    return LoadConfigTyped(
        game_paks_directory=config.get("CONFIG", "game_paks_directory").strip('"'),
        mod_directory=config.get("CONFIG", "mod_directory").strip('"'),
        game_executable_path=config.get("CONFIG", "game_executable_path").strip('"'),
        bypass_sig_dir=config.get("CONFIG", "bypass_sig_dir").strip('"'),
        loader_dir=config.get("CONFIG", "loader_dir").strip('"'),
        binaries_dir=config.get("CONFIG", "binaries_dir").strip('"'),
        game_dir=config.get("CONFIG", "game_dir").strip('"'),
        debug_mode=config.get("CONFIG", "debug_mode").strip('"').lower(),
        debug_dir=config.get("CONFIG", "debug_dir").strip('"'),
        version=config.get("CONFIG", "version").strip('"'),
        dx11=config.get("CONFIG", "dx11").strip('"'),
        logs_folder=config.get("CONFIG", "logs_folder", fallback=DEFAULT_LOGS_FOLDER),
        logs_blocked=config.get("CONFIG", "logs_blocked").strip('"')
    )

# --- Game Version Management ---
def set_game_version():
    while True:
        clear_console()
        print("Select Game Version: \n")
        print("  1. OS Version (Global)")
        print("  2. CN Version ")
        choice = input("Please select a version (1 or 2): ").strip()
        if choice == "1":
            config["CONFIG"]["version"] = "OS"
            with open(CONFIG_FILE, "w") as f:
                config.write(f)
            clear_console()
            time.sleep(2)
            return WW_OS_PAK
        elif choice == "2":
            config["CONFIG"]["version"] = "CN"
            with open(CONFIG_FILE, "w") as f:
                config.write(f)
            clear_console()
            time.sleep(2)
            return WW_CN_PAK
        else:
            clear_console()
            input("Invalid input, press Enter to try again...")
            time.sleep(1)
            clear_console()

def check_game_version() -> str:
    config_data = load_config()
    if config_data["version"] not in ["CN", "OS"]:
        default_ver = set_game_version()
    else:
        default_ver = WW_CN_PAK if config_data["version"] == "CN" else WW_OS_PAK
    with open(resource_path("./pak/bypass/libraries.txt"), "w") as f:
        f.write(default_ver)
    print(f"Game Version: {'Global' if config_data['version'] == 'OS' else 'CN'}")
    return default_ver

# --- Log Blocker Functions ---
def set_folder_permissions(folder_path: str, allow_write: bool = False) -> bool:
    try:
        sd = win32security.GetFileSecurity(folder_path, win32security.DACL_SECURITY_INFORMATION)
        dacl = sd.GetSecurityDescriptorDacl()
        users_sid = win32security.LookupAccountName("", USERS_GROUP)[0]
        print(f"Updating permissions for: {folder_path}")
        
        # Remove existing ACE for Users
        for i in range(dacl.GetAceCount() - 1, -1, -1):
            ace = dacl.GetAce(i)
            if ace[2] == users_sid:
                print(f"  - Removing existing ACE for Users at index {i}")
                dacl.DeleteAce(i)


        if allow_write:
            print("  - Adding ACE to allow read, write and execute")
            dacl.AddAccessAllowedAce(
                win32security.ACL_REVISION,
                con.FILE_GENERIC_READ | con.FILE_GENERIC_WRITE | con.FILE_GENERIC_EXECUTE,
                users_sid,
            )
        else:
            print("  - Adding ACE to allow read and execute")
            dacl.AddAccessAllowedAce(
                win32security.ACL_REVISION,
                con.FILE_GENERIC_READ | con.FILE_GENERIC_EXECUTE,
                users_sid,
            )
            print("  - Adding ACE to deny write")
            dacl.AddAccessDeniedAce(
                win32security.ACL_REVISION,
                con.FILE_GENERIC_WRITE,
                users_sid,
            )

        sd.SetSecurityDescriptorDacl(1, dacl, 0)
        win32security.SetFileSecurity(folder_path, win32security.DACL_SECURITY_INFORMATION, sd)
        logger.info(f"Permissions updated for {folder_path}: {'Write Allowed' if allow_write else 'Write Denied'}")
        print(f"Permissions updated for {folder_path}: {'Write Allowed' if allow_write else 'Write Denied'}")
        return True
    except pywintypes.error as e:
        logger.error(f"Error setting permissions for {folder_path}: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error setting permissions: {e}")
        return False

def get_folder_with_ui() -> Optional[str]:
    root = tk.Tk()
    root.withdraw()
    return filedialog.askdirectory()

def check_log_blocker_status(logs_path: str) -> Tuple[str, str]:
    try:
        test_file = os.path.join(logs_path, "test.txt")
        with open(test_file, "w") as f:
            f.write("test")
        os.remove(test_file)
        status, color = "NOT RUNNING", "\033[91m"
    except PermissionError:
        status, color = "RUNNING", "\033[92m"
    except Exception as e:
        logger.error(f"Error checking status: {e}")
        status, color = "UNKNOWN", "\033[93m"
    return status, color

# --- UI and Menu Functions ---
def get_terminal_size():
    terminal_size = shutil.get_terminal_size()
    return terminal_size.columns, terminal_size.lines

def center_text(text: str, width: int) -> str:
    return text.center(width)

def display_menu_with_cursor(logs_path: str, selected_option: int):
    clear_console()
    status, color = check_log_blocker_status(logs_path)
    term_width, _ = get_terminal_size()
    print("\n")
    print(center_text("Fun-Launcher", term_width))
    print(center_text(f"Logs Path: {logs_path}", term_width))
    print(center_text(f"Current Status: {color}{status}\033[0m", term_width))
    print()
    max_length = max(len(option) for option in MENU_OPTIONS)
    for i, option in enumerate(MENU_OPTIONS):
        padded_option = f"{'→ ' if i == selected_option else '  '}{option}".ljust(max_length + 4)
        print(center_text(f"{'\033[97m' if i == selected_option else ''}{padded_option}\033[0m", term_width))

def get_key():
    while True:
        if msvcrt.kbhit():
            return msvcrt.getch()

# --- Game Launch and Mod Management ---
launch_cancelled = False 

def runProgram(executable_path, args=None):
    global launch_cancelled
    cfg = load_config()
    try:
        if args is None:
            args = []
        logging.info("Starting the game")
        print("This cheat is free. If you bought it, you might have been SCAMMED!")
        print("Credits")
        print("Xoph")
        print("saefulbarkah")
        print("Starting the game, Please wait 5 seconds...")
        time.sleep(5)
        hide_console()
        clear_console()
        process = subprocess.Popen(
            [executable_path] + args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=True,
            close_fds=True,
            cwd=cfg["game_executable_path"],
        )
        stdout, stderr = process.communicate()
        monitorProcess(process)

    except Exception as e:
        print(f"Error running executable: {e}")
        logging.error(f"Error running executable: {e}")

def monitorProcess(process):
    global launch_cancelled
    try:
        while True:
            if process.poll() is not None:
                show_console()
                print("Game closed. Mods will be automatically removed.")
                break
            if launch_cancelled:
                terminateProcess(process)
                print("Game process terminated due to cancellation.")
                break
            time.sleep(5)
    except KeyboardInterrupt:
        print("Stopping game due to interruption.")
        terminateProcess(process)

def terminateProcess(process):
    try:
        process.terminate()
        process.wait(timeout=5)
        logging.info(f"Process terminated.")
    except subprocess.TimeoutExpired:
        logging.info(f"Process did not terminate in time, killing...")
        process.kill()
        process.wait()
        logging.info(f"Process killed.")

def delete_mod_directory(path_dir: str, mod_dir: str):
    try:
        mod_folder_path = os.path.join(path_dir, os.path.basename(mod_dir))
        if os.path.exists(mod_folder_path):
            shutil.rmtree(mod_folder_path)
            logging.info(f"Mod has been deleted.")
        else:
            logging.info(f"Mod does not exist.")
    except Exception as e:
        logging.error(f"Error deleting mod directory: {e}")

def delete_files_from_list(path: str, file_list: List[str]):
    for filename in file_list:
        file_path = os.path.join(path, filename)
        try:
            if os.path.isfile(file_path):
                os.remove(file_path)
            else:
                print(f"'{file_path}' is not a file or does not exist.")
        except Exception as e:
            logging.error(f"Error deleting file '{file_path}': {e}")

def copy_file_or_folder(source: str, target: str, is_folder=False):
    try:
        if is_folder:
            if os.path.exists(target):
                shutil.rmtree(target)
            shutil.copytree(source, target)
            logging.info(f"Folder '{source}' copied to '{target}'")
        else:
            os.makedirs(os.path.dirname(target), exist_ok=True)
            shutil.copy2(resource_path(source), target)
            logging.info(f"File '{os.path.basename(source)}' copied to '{target}'")
    except FileNotFoundError:
          print(f"Error: Source '{source}' not found.")
          logging.error(f"Error: Source '{source}' not found.")
          sys.exit(1)
    except Exception as e:
        print(f"Error copying: {e}")
        logging.error(f"Error copying {source} to {target}: {e}")
        sys.exit(1)

def get_dx11_choice(default_dx11: bool) -> str:
    global launch_cancelled
    while True:
        clear_console()
        print("Run game with DirectX 11?")
        print("1. Yes")
        print("2. No")
        print("3. Always")
        print("Press Ctrl+C to cancel launch")
        choice = input(f"Select option (1/2/3): ").strip()

        if launch_cancelled:
            return "cancel"

        if choice == "1":
            return "yes"
        elif choice == "2":
            return "no"
        elif choice == "3":
            return "always"
        else:
            print("Invalid input. Please select 1, 2, or 3.")
            time.sleep(1)

def install_mods(use_dx11: bool, ver: str):
    cfg = load_config()
    game_pak_dir = cfg["game_paks_directory"]
    game_exe_path = cfg["game_executable_path"]
    print(f"DirectX: {'11' if use_dx11 else '12'}")
    print("Installing mod, please wait...")
    copy_file_or_folder("./pak/bypass/winhttp.dll", os.path.join(game_exe_path, "winhttp.dll"))
    copy_file_or_folder("./pak/bypass/config.json", os.path.join(game_exe_path, "config.json"))
    copy_file_or_folder(f"./pak/bypass/{ver}", os.path.join(game_exe_path, ver))
    copy_file_or_folder("./pak/bypass/libraries.txt", os.path.join(game_exe_path, "libraries.txt"))
    copy_file_or_folder(resource_path(cfg["loader_dir"]), os.path.join(game_pak_dir, "~mods"), is_folder=True)
    copy_file_or_folder(resource_path(cfg["mod_directory"]), os.path.join(cfg["game_dir"], "Mod"), is_folder=True)
    if cfg["debug_mode"] == "true":
        print("Dev mode")
        copy_file_or_folder(resource_path(cfg["debug_dir"]), os.path.join(game_pak_dir, "~mods/"), is_folder=True)
    time.sleep(4)
    clear_console()
    time.sleep(1)

# --- Cleanup on Exit ---
def cleanup():
    try:
        cfg = load_config()
        game_pak_dir = cfg["game_paks_directory"]
        ver = check_game_version()
        filter_files = FILTER_FILES_DELETED + [ver]
        delete_mod_directory(cfg["game_dir"], "Mod")
        delete_mod_directory(game_pak_dir, "~mods")
        delete_files_from_list(cfg["binaries_dir"], filter_files)
        print("Mods removed.")
    except Exception as e:
        logger.error(f"Error during cleanup: {e}")

# Register cleanup() to be called on exit
atexit.register(cleanup)

# --- Main Execution ---
def check_existing_instance():
    count = 0
    for process in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            if process.info['name'] == "python.exe" and __file__ in process.info.get('cmdline', []):
                count += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return count > 1

def main():
    global launch_cancelled
    if os.name != "nt":
        logger.error("This script is only supported on Windows.")
        sys.exit(1)

    if not ctypes.windll.shell32.IsUserAnAdmin():
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit(0)

    if check_existing_instance():
        print("Another instance of Fun-Launcher is already running.")
        time.sleep(3)
        sys.exit(1)

    cfg = load_config()
    logs_path = cfg["logs_folder"]
    selected_option = 0

    parser = argparse.ArgumentParser()
    parser.add_argument("-dx11", action="store_true", help="Enable DirectX 11")
    args = parser.parse_args()

    while True:
        display_menu_with_cursor(logs_path, selected_option)
        key = get_key()
        if key == b"H":
            selected_option = (selected_option - 1) % len(MENU_OPTIONS)
        elif key == b"P":
            selected_option = (selected_option + 1) % len(MENU_OPTIONS)
        elif key == b'\x1b':
            sys.exit(0)
        elif key in [b"\r", b" ", b"M"]:
            if selected_option == 0:
                if is_process_running("Client-Win64-Shipping.exe"):
                    print("Game is currently running. Please close it first.")
                    logging.info("Game is currently running. Please close it first.")
                    input("Press enter to continue...")
                    continue
                
                # Check log blocker status and enable if needed
                status, _ = check_log_blocker_status(logs_path)
                if status == "NOT RUNNING":
                    print("Log blocker is off, Enabling it before launching game...")
                    if set_folder_permissions(logs_path, False):
                        logger.info("Log Blocker enabled successfully (automatic).")
                        print("Log Blocker is now enabled (automatic).")
                        config.set("CONFIG", "logs_blocked", "true")
                        with open(CONFIG_FILE, "w") as f:
                            config.write(f)
                    else:
                        logger.error("Failed to enable Log Blocker (automatic)!")
                        print("Failed to enable Log Blocker (automatic).")
                    time.sleep(2)
                
                ver = check_game_version()
                use_dx11 = args.dx11 or cfg["dx11"] == "true"

                def cancellation_monitor():
                    global launch_cancelled
                    while not launch_cancelled:
                        try:
                            if msvcrt.kbhit():
                                key = msvcrt.getch()
                                if key == b'\x03':
                                    launch_cancelled = True
                                    print("Cancelling launch...")
                                    break
                        except Exception as e:
                            print(f"Error in cancellation monitor: {e}")
                        time.sleep(0.1)

                cancellation_thread = threading.Thread(target=cancellation_monitor)
                cancellation_thread.daemon = True
                cancellation_thread.start()

                if not args.dx11:
                    dx11_choice = get_dx11_choice(cfg["dx11"] == "true")

                    if dx11_choice == "cancel":
                        launch_cancelled = False
                        print("Launch cancelled.")
                        continue

                    if dx11_choice == "yes":
                        use_dx11 = True
                        config.set("CONFIG", "dx11", "true")
                    elif dx11_choice == "no":
                        use_dx11 = False
                        config.set("CONFIG", "dx11", "false")
                    elif dx11_choice == "always":
                        use_dx11 = True
                        config.set("CONFIG", "dx11", "true")
                    with open(CONFIG_FILE, "w") as f:
                        config.write(f)
                launch_cancelled = False
                install_mods(use_dx11, ver)
                run_args = ["-dx11"] if use_dx11 else []
                runProgram(os.path.join(cfg["game_executable_path"], "Client-Win64-Shipping.exe"), args=run_args)
                launch_cancelled = False

            elif selected_option == 1:
                if set_folder_permissions(logs_path, False):
                    logger.info("Log Blocker enabled successfully!")
                    print("Log Blocker is now enabled.")
                    config.set("CONFIG", "logs_blocked", "true")
                    with open(CONFIG_FILE, "w") as f:
                        config.write(f)
                else:
                    logger.error("Failed to enable Log Blocker!")
                    print("Failed to enable Log Blocker.")
                time.sleep(2)
            elif selected_option == 2:
                if set_folder_permissions(logs_path, True):
                    logger.info("Log Blocker disabled successfully!")
                    print("Log Blocker is now disabled.")
                    config.set("CONFIG", "logs_blocked", "false")
                    with open(CONFIG_FILE, "w") as f:
                        config.write(f)
                else:
                    logger.error("Failed to disable Log Blocker!")
                    print("Failed to disable Log Blocker.")
                time.sleep(2)
            elif selected_option == 3:
                new_path = get_folder_with_ui()
                if new_path:
                    logs_path = new_path
                    config.read(CONFIG_FILE)
                    config.set("CONFIG", "logs_folder", new_path)
                    with open(CONFIG_FILE, "w") as f:
                        config.write(f)
                    logger.info(f"Logs path updated to: {logs_path}")
                time.sleep(2)
            elif selected_option == 4:
                sys.exit(0)
            elif selected_option == 5:
                cleanup()
                print("Manual cleanup performed.")
                time.sleep(2)
                
if __name__ == "__main__":
    main()