import argparse
import read_evtx
import read_registry
from utils import functions as own_functions
from scripts.ilapfuncs import logfunc, tsv, timeline, is_platform_windows, \
    OutputParameters, logdevinfo, logfunc
from time import process_time, gmtime, strftime
from scripts.report import generate_report
import os
import datetime

def main(data):
    start = process_time()

    output_format = data.format

    output_folder = data.output
    if not output_folder:
        output_folder = os.getcwd()

    out_params = OutputParameters(output_folder)
    input_path = ''  # TODO

    # ======================= Prepare Output Folder =======================

    logdevinfo()
    logfunc()

    log = open(os.path.join(out_params.report_folder_base, 'Script Logs', 'ProcessedFilesLog.html'), 'w+',
               encoding='utf8')
    nl = '\n'  # literal in order to have new lines in fstrings that create text files
    log.write(f'Extraction/Path selected: {input_path}<br><br>')

    # ======================= File Processing =======================

    if data.eventlog:
        # print(f"Event Log: {data.eventlog}")
        read_evtx.read_evtx_file(data.eventlog, out_params.report_folder_base, input_path, output_format)

    if data.registry:
        # print(f"Registry: {data.registry}")
        read_registry.read_registry_file(data.registry, out_params.report_folder_base, input_path, output_format)

    # ======================= Terminate Report =======================

    end = process_time()
    run_time_secs = end - start
    run_time_HMS = strftime('%H:%M:%S', gmtime(run_time_secs))

    generate_report(out_params.report_folder_base, run_time_secs, run_time_HMS, 'fs', input_path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='passkey-forensics-W11',
        description='''
            Passkey Forensics W11 is a tool to extract and 
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
        "--registry",
        help="Path with registry file",
        required=False,
        default=None,
        type=str)

    parser.add_argument(
        "-o",
        "--output",
        help="Output folder",
        required=False,
        default=None,
        type=str)

    parser.add_argument(
        "-f",
        "--format",
        help="Output format",
        required=True,
        default=None,
        type=str,
        choices=['csv', 'html'])

    args = parser.parse_args()
    main(args)
