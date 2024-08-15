from regipy.registry import RegistryHive
from regipy.utils import convert_wintime
from scripts.artifact_report import ArtifactHtmlReport
from scripts.ilapfuncs import logfunc
import os
from utils import functions as own_functions


# Registry path to search
SEARCH_PATH = fr"S-1-5-20\Software\Microsoft\Cryptography\FIDO"

#--------------------------------------------------------------------
# Formats and writes info when at least one device is found
# 2024-07-26
#--------------------------------------------------------------------
def info_success_to_log(num_devices):
    if num_devices > 1:
        end_S = "s"
    else:
        end_S = ""

    log_S = f"---Success, {num_devices} associated device{end_S} found---"
    logfunc(log_S)


#--------------------------------------------------------------------
# @return Returns -1 on error, the number of FIDO2's devices which 
# have left traces in the registry.
# last updated: 2024-07-26
#--------------------------------------------------------------------
def read_registry_file(registry_file_path, report_folder, output_format):

    reg = RegistryHive(registry_file_path)
    fido_list = {}
    linked_devices = []  # [[<user_id>, <device_name>, <last_modified>, <isCorrupted>, <device_data>], ...]
    logfunc("---Analyzing Registry file---")

    # Count the number of found devices
    count_devices = 0

    try:
        for sk in reg.get_key(SEARCH_PATH).iter_subkeys():
            fido_list[sk.name] = None

        for fido_sk in fido_list:
            device_list = {}

            path = SEARCH_PATH
            path += f'\\' + str(fido_sk) + rf'\LinkedDevices'
            for device_sk in reg.get_key(path).iter_subkeys():
                device_list[device_sk.name] = None

            fido_list[fido_sk] = device_list.copy()
    except:
        logfunc('---No associated devices found---')
        return

    try:
        for fido in fido_list:
            # print(fido)  # User ID
            linked_device = [fido, None, None, None, None] # [<user_id>, <device_name>, <last_modified>, <is_corrupted>, <device_data>]

            for device in fido_list[fido]:

                path = SEARCH_PATH
                path += f'\\' + str(fido) + rf'\LinkedDevices'
                path += f'\\' + str(device)
                data = reg.get_key(path)

                for i in data.get_values():
                    # print("\t\t" + str(i))
                    if i.name == "Name":
                        linked_device[1] = i.value
                        # logfunc(f'\tDevice found: {i.value}')
                    if i.name == "Data" and i.value_type == 'REG_BINARY':
                        linked_device[4] = i.value.hex().upper()
                    linked_device[3] = i.is_corrupted

                linked_device[2] = convert_wintime(data.header.last_modified, as_json=False).strftime("%Y-%m-%d %H:%M:%S")

                # Info to user
                if linked_device[1]:
                    logfunc(f"\tDevice found: '{linked_device[1]}' ({linked_device[2]})")
                    count_devices = count_devices + 1

                linked_devices.append(linked_device.copy())
    except:
        logfunc('---Error extracting data---')
        return -1 
    
    data_headers = ('User ID', 'Device Name', 'Last Modified','Is Corrupted', 'Device Data')
    # DEBUG
    # logfunc(f"{linked_devices=}")

    if output_format == 'csv':
        linked_devices.insert(0, data_headers)
        own_functions.write_csv(os.path.join(report_folder, 'linked_devices.csv'), linked_devices)

        info_success_to_log(count_devices)
        # logfunc('---Sucess, ' + str(len(linked_devices)) + ' associated devices found---')

    elif output_format == 'html':
        if len(linked_devices) > 0:
            report = ArtifactHtmlReport('Passkeys - Registry')
            report.start_artifact_report(report_folder, 'Passkeys - Registry')
            report.add_script()

            report.write_artifact_data_table(data_headers, linked_devices, registry_file_path)
            report.end_artifact_report()

            info_success_to_log(count_devices)
            ## logfunc('---Sucess, ' + str(len(linked_devices)) + ' associated devices found---')
        else:
            logfunc('Passkeys - registry data available')
    
    elif output_format == 'xlsx':
        linked_devices.insert(0, data_headers)
        own_functions.write_excel(os.path.join(report_folder, 'passkeys_artifacts_data.xlsx'), 
                                                    'Linked Devices', linked_devices, is_rewrite=False)

        info_success_to_log(count_devices)
        ## logfunc('---Sucess, ' + str(len(linked_devices)) + ' associated devices found---')

    return count_devices

