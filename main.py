import argparse


def main(data):
    print("Hello World")
    if data.eventlog:
        print(f"Event Log: {data.eventlog}")

    if data.registry:
        print(f"Registry: {data.registry}")


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
        "-r",
        "--registry",
        help="Path with registry file",
        required=False,
        default=None,
        type=str)

    args = parser.parse_args()
    main(args)
