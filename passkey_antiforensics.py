import winreg
import os
import psutil

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
                print(f"Processo {proc.info['name']} (PID: {proc.info['pid']}) está a usar este ficheiro.")
                print(f"A terminar o processo {proc.info['name']} (PID: {proc.info['pid']}) para eliminar o ficheiro.")
                proc.terminate()
                proc.wait()  # Wait for the process to terminate

            # Attempt to delete the file
            os.remove(evtx_file_path)
            print(f"--Ficheiro EVTX eliminado com sucesso {evtx_file_path}--")
        else:
            print(f"O ficheiro {evtx_file_path} não existe.")
    except Exception as e:
        print(f"Ocorreu um erro ao tentar eliminar o ficheiro: {e}")


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
        print("--Os dispositivos associados foram eliminados com sucesso--")
    except:
        print(f"A Chave {key}\\{sub_key_name} não existe ou não foi encontrada")


# Example usage
if __name__ == "__main__":
    print("--- Passkey Anti Forense ---")
    print("A tentar eliminar ficheiro EVTX")
    delete_evtx_file("Microsoft-Windows-WebAuthN%4Operational.evtx")

    print("A tentar eliminar entradas no registry")
    delete_registry_key(winreg.HKEY_USERS, rf"S-1-5-20\Software\Microsoft\Cryptography\FIDO")


