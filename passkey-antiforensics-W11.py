from Evtx.Evtx import Evtx
import winreg
import os
import psutil


def delete_registry_key_recursive(hive, subkey):
    """
    Recursively deletes a registry key and all its subkeys/values.

    :param hive: The hive constant (e.g., winreg.HKEY_USERS).
    :param subkey: The subkey path.
    """
    try:
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_ALL_ACCESS) as key:
            # Get the subkeys and recursively delete them
            i = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    delete_registry_key_recursive(hive, f"{subkey}\\{subkey_name}")
                except OSError:
                    break
                i += 1
            winreg.DeleteKey(key, "")
            print(f"Successfully deleted key {hive}\\{subkey}")
    except FileNotFoundError:
        print(f"The specified registry key does not exist: {hive}\\{subkey}")
    except PermissionError:
        print(f"Permission denied. Please run the script as an administrator.")
    except Exception as e:
        print(f"An error occurred while trying to delete the registry key: {e}")
        
def find_process_using_file(file_path):
    """
    Find the process using the specified file.

    :param file_path: The path to the file.
    :return: The process using the file, or None if no process is found.
    """
    for proc in psutil.process_iter(['pid', 'name', 'open_files']):
        try:
            open_files = proc.info['open_files']
            if open_files:
                for open_file in open_files:
                    if open_file.path == file_path:
                        return proc
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            continue
    return None


def delete_evtx_file(evtx_filename):
    """
    Deletes the specified EVTX file from the logs directory.

    :param evtx_filename: The name of the EVTX file to delete.
    """
    # Construct the full path to the EVTX file
    evtx_file_path = os.path.join("C:\\Windows\\System32\\winevt\\Logs", evtx_filename)

    try:
        # Check if the file exists
        if os.path.exists(evtx_file_path):
            # Find the process using the file
            proc = find_process_using_file(evtx_file_path)
            if proc:
                print(f"Process {proc.info['name']} (PID: {proc.info['pid']}) is using the file.")
                print(f"Terminating process {proc.info['name']} (PID: {proc.info['pid']}).")
                proc.terminate()
                proc.wait()  # Wait for the process to terminate

            # Attempt to delete the file
            os.remove(evtx_file_path)
            print(f"Successfully deleted {evtx_file_path}")
        else:
            print(f"The file {evtx_file_path} does not exist.")
    except Exception as e:
        print(f"An error occurred while trying to delete the file: {e}")


# Example usage
if __name__ == "__main__":

    hive = winreg.HKEY_USERS
    subkey = r"\S-1-5-20\Software\Microsoft\Cryptography\FIDO"

    # Call the function to delete the registry key
    delete_registry_key_recursive(hive, subkey)

    # Define the EVTX file name
    evtx_filename = "Microsoft-Windows-WebAuthN%4Operational.evtx"

    # Call the function to delete the EVTX file
    delete_evtx_file(evtx_filename)
