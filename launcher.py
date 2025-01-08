import os
import shutil
from tkinter.filedialog import askdirectory
from configparser import ConfigParser
import subprocess
import time
import ctypes
from typing import TypedDict
import sys
import psutil
import logging
import argparse

log_file = "launcher.log"
logging.basicConfig(
    filename=log_file,
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

config = ConfigParser()

filter_file_deleted = [
    "config.json",
    "libraries.txt",
    "winhttp.dll",
]
ww_os_pak = "CenSerPatch-OS.dll"
ww_cn_pak = "CenSerPatch-CN.dll"


def hide_console():
    # Get the current console window
    hwnd = ctypes.windll.kernel32.GetConsoleWindow()
    if hwnd:
        # Hide the console window
        ctypes.windll.user32.ShowWindow(hwnd, 0)


def clear_console():
    """Clear the console based on the operating system."""
    os.system("cls" if os.name == "nt" else "clear")


def show_console():
    # Get the current console window
    hwnd = ctypes.windll.kernel32.GetConsoleWindow()
    if hwnd:
        # Show the console window
        ctypes.windll.user32.ShowWindow(hwnd, 5)  # 5 = SW_SHOW


def is_process_running(process_name: str) -> bool:
    """Check if a process with the given name is running."""
    for process in psutil.process_iter(["name"]):
        if process.info["name"] == process_name:
            return True
    return False


def checkConfigExists():
    return os.path.exists("config.ini")


def createDefaultConfig():
    if not checkConfigExists():
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

        with open("config.ini", "w") as configFile:
            config.write(configFile)
        print("config.ini created with default settings.")


def saveGameDirectory():
    path = askdirectory(title="Select Wuthering Wave Game Folder")
    if path:
        config.read("config.ini")
        if not config.has_section("CONFIG"):
            config.add_section("CONFIG")
        # Set Game folder
        gamePaksPath = os.path.join(path, "Client", "Content", "Paks")
        gameExecutablePath = os.path.join(
            path,
            "Client",
            "Binaries",
            "Win64",
        )
        binaries_path = os.path.join(path, "Client", "Binaries", "Win64")
        game_dir = os.path.join(
            path,
        )
        config.set("CONFIG", "game_executable_path", gameExecutablePath)
        config.set("CONFIG", "game_paks_directory", gamePaksPath)
        config.set("CONFIG", "binaries_dir", binaries_path)
        config.set("CONFIG", "game_dir", game_dir)
        # Save config file
        with open("config.ini", "w") as configFile:
            config.write(configFile)


def checkAndSaveConfig():
    createDefaultConfig()
    config.read("config.ini")

    if not config.has_section("CONFIG"):
        print("CONFIG section is missing, creating default config.")
        createDefaultConfig()

    if not config.has_option("CONFIG", "game_paks_directory"):
        print("Wuthering Waves not found, Select Wuthering Wave Game folder.")
        saveGameDirectory()

    if not config.has_option("CONFIG", "version"):
        setGameVersion()

    game_folder = config.get("CONFIG", "game_paks_directory").strip('"')

    if not game_folder:
        print("Game not found, Select Wuthering Wave Game folder.")
        saveGameDirectory()


class loadTyped(TypedDict):
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


def loadConfig() -> loadTyped:
    config.read("config.ini")
    try:
        game_paks_directory = config.get("CONFIG", "game_paks_directory").strip('"')
        mod_directory = config.get("CONFIG", "mod_directory").strip('"')
        game_executable_path = config.get("CONFIG", "game_executable_path").strip('"')
        bypass_sig_dir = config.get("CONFIG", "bypass_sig_dir").strip('"')
        loader_dir = config.get("CONFIG", "loader_dir").strip('"')
        binaries_dir = config.get("CONFIG", "binaries_dir").strip('"')
        game_dir = config.get("CONFIG", "game_dir").strip('"')
        debug_mode = config.get("CONFIG", "debug_mode").strip('"').lower()
        debug_dir = config.get("CONFIG", "debug_dir").strip('"')
        version = config.get("CONFIG", "version").strip('"')
        dx11 = config.get("CONFIG", "dx11").strip('"')
        return {
            "game_paks_directory": game_paks_directory,
            "mod_directory": mod_directory,
            "game_executable_path": game_executable_path,
            "bypass_sig_dir": bypass_sig_dir,
            "loader_dir": loader_dir,
            "binaries_dir": binaries_dir,
            "game_dir": game_dir,
            "debug_mode": debug_mode,
            "debug_dir": debug_dir,
            "version": version,
            "dx11": dx11,
        }
    except Exception as e:
        print(f"Error reading config: {e}")
        return None, None, None


def runProgram(executable_path, args=None):
    cfg = loadConfig()
    try:
        if args is None:
            args = []
        logging.info("Starting the game")
        print("This cheat is free. If you bought it, you might have been SCAMMED!")
        print("Credits: Xoph")
        print("Starting the game, Please wait 5 seconds...")
        time.sleep(5)
        hide_console()
        clear_console()
        # Start the process without admin privileges
        process = subprocess.Popen(
            [executable_path] + args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=True,  # This opens a new shell to execute the command
            close_fds=True,  # Close file descriptors
            cwd=cfg["game_executable_path"],
        )

        # Optionally, capture the output
        stdout, stderr = process.communicate()
        monitorProcess(process)

    except Exception as e:
        print(f"Error running executable: {e}")
        logging.error(f"Error running executable: {e}")


def monitorProcess(process):
    try:
        while True:
            if process.poll() is not None:  # Check if the process has terminated
                show_console()
                break  # Exit the loop if the process has terminated

            time.sleep(5)  # Check every 5 seconds
    except KeyboardInterrupt:
        print("Stopping game due to interruption.")
        terminateProcess(process)


def terminateProcess(process):
    try:
        process.terminate()
        process.wait(timeout=5)
        # print("Process terminated.")
        logging.info(f"Process terminated.")

    except subprocess.TimeoutExpired:
        logging.info(f"Process did not terminate in time, killing...")
        # print("Process did not terminate in time, killing...")
        process.kill()
        process.wait()
        # print("Process killed.")
        logging.info(f"Process killed.")


def deleteModDirectory(pathDir: str, mod_dir: str):
    try:
        mod_folder_path = os.path.join(pathDir, os.path.basename(mod_dir))
        if os.path.exists(mod_folder_path):
            shutil.rmtree(mod_folder_path)
            logging.info(f"Mod has been deleted.")
        else:
            logging.info(f"Mod does not exists.")
    except Exception as e:
        logging.error(f"Error deleting mod directory: {e}")


def delete_files_from_list(path, file_list):
    for filename in file_list:
        file_path = os.path.join(path, filename)  # Combine path and filename

        try:
            if os.path.isfile(file_path):  # Check if it's a file
                os.remove(file_path)  # Delete the file
                # print(f"File mod has been deleted.")
            else:
                print(f"'{file_path}' is not a file or does not exist.")
        except Exception as e:
            logging.error(f"Error deleting file '{file_path}': {e}")
            # print(f"Error deleting file '{file_path}': {e}")


def force_close_process_windows(process_name):
    try:
        subprocess.run(["taskkill", "/f", "/im", process_name], check=True)
        print(f"Killed: {process_name}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to kill process: {e}")
        return sys.exit(1)
    except Exception as e:
        logging.error(f"Error: {e}")
        return sys.exit(1)


def copyFilesToGameDirectory(target_directory, source_folder):
    # Ensure target directory exists
    if not os.path.exists(target_directory):
        os.makedirs(target_directory)

    # Iterate over all files in the source folder
    try:
        for filename in os.listdir(source_folder):
            source_file = os.path.join(source_folder, filename)
            target_file = os.path.join(target_directory, filename)

            if os.path.isfile(source_file):
                shutil.copy2(source_file, target_file)
                logging.info(
                    f"File '{filename}' successfully copied to '{target_directory}'."
                )
            else:
                print(f"'{filename}' is not a file and was skipped.")
    except Exception as e:
        print(f"Error copying files: {e}")
        logging.error(f"Error copying files: {e}")


def copyFileToGameDirectory(target_directory, source_file):
    # Ensure target directory exists
    if not os.path.exists(target_directory):
        os.makedirs(target_directory)

    # Ensure the source file exists
    if not os.path.isfile(source_file):
        print(f"Source file '{source_file}' does not exist.")
        logging.error(f"Source file '{source_file}' does not exist.")
        return sys.exit(1)

    # Get the filename from the source path
    filename = os.path.basename(source_file)
    target_file = os.path.join(target_directory, filename)

    try:
        # Copy the file to the target directory
        shutil.copy2(source_file, target_file)
        logging.info(f"File '{filename}' successfully copied to '{target_directory}'.")
    except Exception as e:
        print(f"Error copying file: {e}")
        logging.error(f"Error copying file: {e}")
        return sys.exit(1)


def copyFolderToGameDirectory(target_directory, source_folder):
    target_folder = os.path.join(target_directory, os.path.basename(source_folder))
    try:
        if os.path.exists(target_folder):
            shutil.rmtree(target_folder)
        shutil.copytree(source_folder, target_folder)
        logging.info(
            f"Folder '{source_folder}' successfully copied to '{target_folder}'."
        )
    except Exception as e:
        logging.error(f"Error copying folder: {e}")
        print(f"Error copying folder: {e}")


def setGameVersion():
    while True:
        clear_console()
        print("Select Game Version: \n")
        print("  1. OS Version (Global)")
        print("  2. CN Version ")
        print("\nPlease select a version (1 or 2): ", end="")

        ver = input().strip()

        if ver == "1":
            config.set("CONFIG", "version", "OS")
            with open("config.ini", "w") as configfile:
                config.write(configfile)  # Save the config to the file
            clear_console()
            time.sleep(2)
            return ww_os_pak  # Ensure the function exits after setting the version

        elif ver == "2":
            config.set("CONFIG", "version", "CN")
            with open("config.ini", "w") as configfile:
                config.write(configfile)  # Save the config to the file
            clear_console()
            time.sleep(2)
            return ww_cn_pak  # Ensure the function exits after setting the version

        else:
            clear_console()
            input("Invalid input, press Enter to try again...")
            time.sleep(1)
            clear_console()


def checkGameVersion():
    config = loadConfig()
    defaultGameVer = ""

    # Check if the version is valid (either "CN" or "OS")
    if config["version"] != "CN" and config["version"] != "OS":
        defaultGameVer = setGameVersion()

    # Set the default game version based on config
    if config["version"] == "CN":
        defaultGameVer = ww_cn_pak

    if config["version"] == "OS":
        defaultGameVer = ww_os_pak

    # Write the selected game version to the file
    with open("./pak/bypass/libraries.txt", "w") as file:
        file.write(defaultGameVer)

    if config["version"] == "OS":
        print("Game Version: Global")
    if config["version"] == "CN":
        print("Game Version: CN")

    return defaultGameVer


def runningGame():
    if is_process_running("Client-Win64-Shipping.exe"):
        print(
            "Game is currently running, Go to task manager, end task process name Wuthering Waves"
        )
        logging.info(
            "Game is currently running, Go to task manager, end task process name Wuthering Waves"
        )
        input("Press enter to exit.....")
        return sys.exit(1)
    print("Version 2.0")
    parser = argparse.ArgumentParser()
    parser.add_argument("-dx11", action="store_true", help="Enable DirectX 11")
    args = parser.parse_args()

    try:
        checkAndSaveConfig()
        config = loadConfig()
        game_pak_dir = config["game_paks_directory"]
        mod_dir = config["mod_directory"]
        game_executable_path = config["game_executable_path"]
        bypass_sig = config["bypass_sig_dir"]
        loader_dir = config["loader_dir"]
        binaries_dir = config["binaries_dir"]
        game_dir = config["game_dir"]
        debug_mode = config["debug_mode"]
        debug_dir = config["debug_dir"]
        dx11 = config["dx11"]

        if game_pak_dir:
            if os.path.exists(game_executable_path):
                getVersion = checkGameVersion()
                if args.dx11 or dx11 == "true":
                    print("DirectX: 11")
                else:
                    print("DirectX: 12")
                print("Installing mod, please wait...")
                # copyFilesToGameDirectory(game_executable_path, bypass_sig)
                copyFileToGameDirectory(
                    game_executable_path, "./pak/bypass/winhttp.dll"
                )
                copyFileToGameDirectory(
                    game_executable_path, "./pak/bypass/config.json"
                )
                copyFileToGameDirectory(
                    game_executable_path, f"./pak/bypass/{getVersion}"
                )
                copyFileToGameDirectory(
                    game_executable_path, f"./pak/bypass/libraries.txt"
                )
                copyFolderToGameDirectory(game_pak_dir, loader_dir)
                copyFolderToGameDirectory(game_dir, mod_dir)
                filter_file_deleted.extend([getVersion])
                if debug_mode == "true":
                    print("Dev mode")
                    copyFilesToGameDirectory(
                        os.path.join(game_pak_dir, "~mods/"), debug_dir
                    )
                time.sleep(4)
                clear_console()
                time.sleep(1)
                if args.dx11 or dx11 == "true":
                    runProgram(
                        os.path.join(
                            game_executable_path,
                            "Client-Win64-Shipping.exe",
                        ),
                        args=["-dx11"],
                    )
                else:
                    print("DirectX: 12")
                    runProgram(
                        os.path.join(
                            game_executable_path,
                            "Client-Win64-Shipping.exe",
                        ),
                        args=[],  # No arguments
                    )
                print("Removing mod, please wait 5 seconds...")
                time.sleep(1)
                deleteModDirectory(game_dir, "Mod")
                deleteModDirectory(game_pak_dir, "~mods")
                delete_files_from_list(binaries_dir, filter_file_deleted)
                time.sleep(4)
            else:
                print(
                    f"Executable '{game_executable_path}' does not exist make sure select Wuthering Wave Game folder, Try to delete config.ini"
                )
                logging.error(
                    f"Executable '{game_executable_path}' does not exist make sure select Wuthering Wave Game folder, Try to delete config.ini"
                )
        else:

            logging.error("Invalid directories specified in config.")
            print("Invalid directories specified in config.")
    except Exception as e:
        logging.error(f"{e}")


if __name__ == "__main__":
    runningGame()