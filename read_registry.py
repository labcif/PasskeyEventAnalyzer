from regipy.registry import RegistryHive
from utils import functions as own_functions

FILE_PATH = fr"windows-registry\2024-03-28_00.00\NTUSER.DAT"
SEARCH_PATH = fr"\Software\Microsoft\Cryptography\FIDO"


def read_registry_file(registry_file_path):
    reg = RegistryHive(registry_file_path)
    fido_list = {}
    linked_devices = [["User ID", "Device Name", "Device Data", "is Corrupted"]]  # [[<user_id>, <device_name>, <device_data>, <isCorrupted>], ...]

    for sk in reg.get_key(SEARCH_PATH).iter_subkeys():
        fido_list[sk.name] = None

    for fido_sk in fido_list:
        device_list = {}

        path = rf'\Software\Microsoft\Cryptography\FIDO'
        path += f'\\' + str(fido_sk) + rf'\LinkedDevices'
        for device_sk in reg.get_key(path).iter_subkeys():
            device_list[device_sk.name] = None

        fido_list[fido_sk] = device_list.copy()

    for fido in fido_list:
        # print(fido)  # User ID
        linked_device = [fido, None, None, None]  # [<user_id>, <device_name>, <device_data>, <isCorrupted>]

        device_element = []
        for device in fido_list[fido]:
            # print("\t" + device)
            device_element.append(device)

            path = rf'\Software\Microsoft\Cryptography\FIDO'
            path += f'\\' + str(fido) + rf'\LinkedDevices'
            path += f'\\' + str(device)
            data = reg.get_key(path).get_values()
            for i in data:
                # print("\t\t" + str(i))
                if i.name == "Name":
                    linked_device[1] = i.value
                if i.name == "Data" and i.value_type == 'REG_BINARY':
                    linked_device[2] = i.value.hex().upper()
                linked_device[3] = i.is_corrupted

            linked_devices.append(linked_device.copy())

    own_functions.write_csv('output_files/linked_devices.csv', linked_devices)


if __name__ == '__main__':
    read_registry_file(FILE_PATH)
