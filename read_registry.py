from regipy.registry import RegistryHive

FILE_PATH = fr"windows-registry\NTUSER.DAT"
SEARCH_PATH = fr"\Software\Microsoft\Cryptography\FIDO"


def main():
    reg = RegistryHive(FILE_PATH)
    fido_list = {}

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
        print(fido)

        for device in fido_list[fido]:
            print("\t" + device)

            path = rf'\Software\Microsoft\Cryptography\FIDO'
            path += f'\\' + str(fido) + rf'\LinkedDevices'
            path += f'\\' + str(device)
            a = reg.get_key(path).get_values()
            for i in a:
                print("\t\t" + str(i))


if __name__ == '__main__':
    main()
