from regipy.registry import RegistryHive

FILE_PATH = fr"NTUSER.DAT"

def main():
    reg = RegistryHive(FILE_PATH)
    device_list = []
    for sk in reg.get_key(
            rf'\Software\Microsoft\Cryptography\FIDO\S-1-5-21-3469369403-1375254044-481706203-1001\LinkedDevices').iter_subkeys():
        device_list.append(sk.name)

    for device in device_list:
        path = rf'\Software\Microsoft\Cryptography\FIDO\S-1-5-21-3469369403-1375254044-481706203-1001\LinkedDevices'
        path += f'\\' + str(device)
        a = reg.get_key(path).get_values()
        print(device)
        for i in a:
            print("\t" + str(i))


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    main()
