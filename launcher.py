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

LOG_FILE = "ww_tweaks.log"
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
]

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("WW-Tweaks")
config = ConfigParser()

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

def check_config_exists():
    return os.path.exists(CONFIG_FILE)

def create_default_config():
    if not check_config_exists():
        config.add_section("CONFIG")
        config.set("CONFIG", "game_paks_directory", "")
        config.set("CONFIG", "game_executable_path", "")
        config.set("CONFIG", "binaries_dir", "")
        config.set("CONFIG", "game_dir", "")
        config.set("CONFIG", "loader_dir", "./pak/loader/~mods")
        config.set("CONFIG", "bypass_sig_dir", "./pak/bypass")
        config.set("CONFIG", "debug_dir", "./pak/debug")
        config.set("CONFIG", "mod_directory", "./pak/Mod")
        config.set("CONFIG", "debug_mode", "false")
        config.set("CONFIG", "version", "")
        config.set("CONFIG", "dx11", "true")
        config.set("CONFIG", "logs_folder", DEFAULT_LOGS_FOLDER)
        config.set("CONFIG", "logs_blocked", "false")
        with open(CONFIG_FILE, "w") as f:
            config.write(f)
        logger.info("config.ini created with default settings.")

def save_game_directory():
    path = askdirectory(title="Select Wuthering Wave Game Folder")
    if path:
        if not is_valid_game_directory(path):
            print("Invalid game directory selected. Please choose a valid directory.")
            logger.error("Invalid game directory selected.")
            return
        config.read(CONFIG_FILE)
        if not config.has_section("CONFIG"):
            config.add_section("CONFIG")
        game_paks_path = os.path.join(path, "Client", "Content", "Paks")
        game_exe_path = os.path.join(path, "Client", "Binaries", "Win64")
        binaries_path = os.path.join(path, "Client", "Binaries", "Win64")
        game_dir = os.path.join(path)
        config.set("CONFIG", "game_executable_path", game_exe_path)
        config.set("CONFIG", "game_paks_directory", game_paks_path)
        config.set("CONFIG", "binaries_dir", binaries_path)
        config.set("CONFIG", "game_dir", game_dir)
        with open(CONFIG_FILE, "w") as f:
            config.write(f)

def is_valid_game_directory(path: str) -> bool:
    required_files = ["Client-Win64-Shipping.exe"]
    return all(os.path.exists(os.path.join(path, "Client", "Binaries", "Win64", file)) for file in required_files)

def check_and_save_config():
    create_default_config()
    config.read(CONFIG_FILE)

    if not config.has_section("CONFIG"):
        logger.warning("CONFIG section is missing, creating default config.")
        create_default_config()

    if not config.has_option("CONFIG", "game_paks_directory") or not config.get("CONFIG", "game_paks_directory"):
        logger.warning("Wuthering Waves not found, select Wuthering Wave Game folder.")
        save_game_directory()

    if not config.has_option("CONFIG", "version") or not config.get("CONFIG", "version"):
        set_game_version()

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

def load_config() -> LoadConfigTyped:
    config.read(CONFIG_FILE)
    try:
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
    except (ConfigParser.NoSectionError, ConfigParser.NoOptionError) as e:
        logger.error(f"Error reading config: {e}")
        print(f"Error: Configuration issue. Please check {CONFIG_FILE}.")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error reading config: {e}")
        print(f"An unexpected error occurred. Please check {LOG_FILE} for details.")
        sys.exit(1)

def run_program(executable_path, args=None):
    cfg = load_config()
    try:
        if args is None:
            args = []
        logging.info("Starting the game")
        print("This cheat is free. If you bought it, you might have been SCAMMED!")
        print("Credits: Xoph")
        print("Starting the game, Please wait...")
        time.sleep(5)
        hide_console()
        clear_console()
        process = subprocess.Popen(
            [executable_path] + args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cfg["game_executable_path"],
        )
        monitor_thread = threading.Thread(target=monitor_process, args=(process,))
        monitor_thread.daemon = True
        monitor_thread.start()
        return process
    except FileNotFoundError:
        logger.error(f"Executable not found: {executable_path}")
        print(f"Error: Executable not found at {executable_path}. Check game installation.")
        show_console()
        return None
    except Exception as e:
        logger.error(f"Error running executable: {e}")
        print(f"An unexpected error occurred: {e}")
        show_console()
        return None

def prompt_disable_log_blocker():
    while True:
        clear_console()
        print("Game closed. Checking if logs are blocked...")
        logs_path = load_log_config()
        if not check_log_blocker_status(logs_path)[0] == "RUNNING":
            print("Logs are already unblocked.")
            time.sleep(2)
            main()
            break
        else:
            print("Logs are blocked. Disabling log blocker...")
            if set_folder_permissions(logs_path, True):
                print("Log Blocker is now disabled.")
                config.set("CONFIG", "logs_blocked", "false")
                with open(CONFIG_FILE, "w") as f:
                    config.write(f)
            else:
                print("Failed to disable Log Blocker.")
            time.sleep(2)
            main()
            break

def monitor_process(process):
    try:
        while True:
            if process.poll() is not None:
                show_console()
                prompt_disable_log_blocker()
                cleanup()
                break
            time.sleep(5)
    except KeyboardInterrupt:
        print("Stopping game due to interruption.")
        terminate_process(process)

def terminate_process(process):
    try:
        process.terminate()
        process.wait(timeout=5)
        logging.info(f"Process terminated.")
    except subprocess.TimeoutExpired:
        logging.info(f"Process did not terminate, killing...")
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

def force_close_process_windows(process_name: str):
    try:
        subprocess.run(["taskkill", "/f", "/im", process_name], check=True)
        print(f"Killed: {process_name}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to kill process: {e}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Error: {e}")
        sys.exit(1)

def copy_file_or_folder(source: str, target: str, is_folder=False):
    try:
        if is_folder:
            if os.path.exists(target):
                shutil.rmtree(target)
            shutil.copytree(source, target)
            logging.info(f"Folder '{source}' copied to '{target}'")
        else:
            os.makedirs(os.path.dirname(target), exist_ok=True)
            shutil.copy2(source, target)
            logging.info(f"File '{os.path.basename(source)}' copied to '{target}'")
    except FileNotFoundError:
          print(f"Error: Source '{source}' not found.")
          logging.error(f"Error: Source '{source}' not found.")
          sys.exit(1)
    except Exception as e:
        print(f"Error copying: {e}")
        logging.error(f"Error copying {source} to {target}: {e}")
        sys.exit(1)

def set_game_version():
    while True:
        clear_console()
        print("Select Game Version: \n")
        print("  1. OS Version (Global)")
        print("  2. CN Version ")
        choice = input("Please select a version (1 or 2): ").strip()
        if choice == "1":
            config.set("CONFIG", "version", "OS")
            with open(CONFIG_FILE, "w") as f:
                config.write(f)
            clear_console()
            time.sleep(2)
            return WW_OS_PAK
        elif choice == "2":
            config.set("CONFIG", "version", "CN")
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

def check_game_version():
    config_data = load_config()
    if config_data["version"] not in ["CN", "OS"]:
        default_ver = set_game_version()
    else:
        default_ver = WW_CN_PAK if config_data["version"] == "CN" else WW_OS_PAK
    with open("./pak/bypass/libraries.txt", "w") as f:
        f.write(default_ver)
    print(f"Game Version: {'Global' if config_data['version'] == 'OS' else 'CN'}")
    return default_ver

def set_folder_permissions(folder_path: str, allow_write: bool = False) -> bool:
    try:
        sd = win32security.GetFileSecurity(folder_path, win32security.DACL_SECURITY_INFORMATION)
        dacl = sd.GetSecurityDescriptorDacl()
        users_sid = win32security.LookupAccountName("", USERS_GROUP)[0]
        for i in range(dacl.GetAceCount() - 1, -1, -1):
            if dacl.GetAce(i)[2] == users_sid:
                 dacl.DeleteAce(i)
        access = con.FILE_GENERIC_READ | con.FILE_GENERIC_EXECUTE
        if allow_write:
            access |= con.FILE_GENERIC_WRITE
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, access, users_sid)
        if not allow_write:
            dacl.AddAccessDeniedAce(win32security.ACL_REVISION, con.FILE_GENERIC_WRITE, users_sid)
        sd.SetSecurityDescriptorDacl(1, dacl, 0)
        win32security.SetFileSecurity(folder_path, win32security.DACL_SECURITY_INFORMATION, sd)
        logger.info(f"Permissions updated for {folder_path}: {'Write Allowed' if allow_write else 'Write Denied'}")
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

def load_log_config() -> str:
    config.read(CONFIG_FILE)
    logs_folder = config.get("CONFIG", "logs_folder", fallback=DEFAULT_LOGS_FOLDER)
    if not os.path.exists(logs_folder):
        logger.warning(f"Logs folder not found: {logs_folder}")
        logs_folder = get_folder_with_ui()
        if not logs_folder:
            logger.error("No folder selected. Exiting.")
            sys.exit(1)
        config.set("CONFIG", "logs_folder", logs_folder)
        with open(CONFIG_FILE, "w") as f:
            config.write(f)
        logger.info(f"Updated config with logs folder: {logs_folder}")
    return logs_folder

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
    print(center_text("Wuthering Waves Tweaks", term_width))
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
    if os.name != "nt":
        logger.error("This script is only supported on Windows.")
        sys.exit(1)
    if not ctypes.windll.shell32.IsUserAnAdmin():
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit(0)
    if check_existing_instance():
        print("Another instance of WW-Tweaks is already running.")
        time.sleep(3)
        sys.exit(1)
    check_and_save_config()
    logs_path = load_log_config()
    selected_option = 0
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
                process = running_game()
                if process:
                    monitor_thread = threading.Thread(target=monitor_process, args=(process,))
                    monitor_thread.daemon = True
                    monitor_thread.start()
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

def running_game():
    if is_process_running("Client-Win64-Shipping.exe"):
        print("Game is currently running. Please close it first.")
        logging.info("Game is currently running. Please close it first.")
        input("Press enter to continue...")
        return None
    print("Version 2.0")
    parser = argparse.ArgumentParser()
    parser.add_argument("-dx11", action="store_true", help="Enable DirectX 11")
    args = parser.parse_args()
    try:
        cfg = load_config()
        game_pak_dir = cfg["game_paks_directory"]
        game_exe_path = cfg["game_executable_path"]
        if game_pak_dir and os.path.exists(game_exe_path):
            ver = check_game_version()
            
            use_dx11 = args.dx11 or cfg["dx11"] == "true"
            if not args.dx11:
                dx11_choice = get_dx11_choice(cfg["dx11"] == "true")
                if dx11_choice == "yes":
                    use_dx11 = True
                    config.set("CONFIG", "dx11", "true")
                    with open(CONFIG_FILE, "w") as f:
                         config.write(f)
                elif dx11_choice == "no":
                    use_dx11 = False
                    config.set("CONFIG", "dx11", "false")
                    with open(CONFIG_FILE, "w") as f:
                         config.write(f)
                elif dx11_choice == "always":
                    use_dx11 = True
                    config.set("CONFIG", "dx11", "true")
                    with open(CONFIG_FILE, "w") as f:
                         config.write(f)
            
            print(f"DirectX: {'11' if use_dx11 else '12'}")
            print("Installing mod, please wait...")
            copy_file_or_folder( "./pak/bypass/winhttp.dll",  os.path.join(game_exe_path, "winhttp.dll"))
            copy_file_or_folder( "./pak/bypass/config.json",  os.path.join(game_exe_path, "config.json"))
            copy_file_or_folder( f"./pak/bypass/{ver}",  os.path.join(game_exe_path, ver))
            copy_file_or_folder( "./pak/bypass/libraries.txt",  os.path.join(game_exe_path, "libraries.txt"))
            copy_file_or_folder(cfg["loader_dir"], os.path.join(game_pak_dir,  "~mods"), is_folder=True)
            copy_file_or_folder(cfg["mod_directory"], os.path.join(cfg["game_dir"], "Mod"), is_folder=True)
            if cfg["debug_mode"] == "true":
                print("Dev mode")
                copy_file_or_folder(cfg["debug_dir"], os.path.join(game_pak_dir, "~mods/"), is_folder=True)
            time.sleep(4)
            clear_console()
            time.sleep(1)
            run_args = ["-dx11"] if use_dx11 else []
            process = run_program(os.path.join(game_exe_path, "Client-Win64-Shipping.exe"), args=run_args)
            if process:
                print("Removing mod, please wait...")
                time.sleep(1)
                return process
            else:
                return None
        else:
            print(f"Executable '{game_exe_path}' not found. Ensure correct game folder. Try deleting config.ini.")
            logging.error(f"Executable '{game_exe_path}' not found. Ensure correct game folder. Try deleting config.ini.")
            return None
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        return None
        
def get_dx11_choice(default_dx11: bool) -> str:
    while True:
        clear_console()
        print("Run game with DirectX 11?")
        print("1. Yes")
        print("2. No")
        print("3. Always")
        choice = input(f"Select option (1/2/3): ").strip()
        if choice == "1":
            return "yes"
        elif choice == "2":
            return "no"
        elif choice == "3":
            return "always"
        else:
            print("Invalid input. Please select 1, 2, or 3.")
            time.sleep(1)

def cleanup():
    cfg = load_config()
    game_pak_dir = cfg["game_paks_directory"]
    ver = check_game_version()
    filter_files = FILTER_FILES_DELETED + [ver]
    delete_mod_directory(cfg["game_dir"], "Mod")
    delete_mod_directory(game_pak_dir, "~mods")
    delete_files_from_list(cfg["binaries_dir"], filter_files)
    print("Mods removed.")

if __name__ == "__main__":
    main()