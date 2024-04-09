import argparse
import read_evtx
import read_registry
from utils import functions as own_functions


def main(data):
    if data.eventlog:
        print(f"Event Log: {data.eventlog}")
        read_evtx.read_evtx_file(data.eventlog)

    if data.registry:
        print(f"Registry: {data.registry}")
        read_registry.read_registry_file(data.registry)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='PassKeysForensics',
        description='''
            PassKeysForensics is a tool to extract and 
            analyze FIDO2 keys from Windows Event Logs and Registry''',
        epilog='Developed by: Pedro Chen and Bruno Correia')

    parser.add_argument(
        "-el",
        "--eventlog",
        help="Path with event log file",
        required=False,
        default=None,
        type=str)

    parser.add_argument(
        "-rf",
        "--registryfile",
        help="Path with registry file",
        required=False,
        default=None,
        type=str)

    args = parser.parse_args()
    main(args)
