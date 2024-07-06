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

    startdate = data.startdate
    enddate = data.enddate
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

    print('- ANALISADOR FORENSE PASSKEYS - ', strftime("%d/%m/%Y %H:%M:%S"))
    if data.eventlog:
        # print(f"Event Log: {data.eventlog}")
        read_evtx.read_evtx_file(data.eventlog, out_params.report_folder_base, input_path, output_format, startdate, enddate)

    if data.registry:
        # print(f"Registry: {data.registry}")
        read_registry.read_registry_file(data.registry, out_params.report_folder_base, input_path, output_format)

    print('TERMINADO - para mais detalhes consulte os resultados na pasta de output.')
    # ======================= Terminate Report =======================

    end = process_time()
    run_time_secs = end - start
    run_time_HMS = strftime('%H:%M:%S', gmtime(run_time_secs))

    print(f'Tempo decorrido: {run_time_HMS}')

    generate_report(out_params.report_folder_base, run_time_secs, run_time_HMS, 'fs', input_path)



if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='PEA',
        description='''
            Passkey Event Analyzer is a tool to extract and 
            analyze FIDO2 keys from Windows Event Logs and Registry''',
        epilog='Developed by: Pedro Chen and Bruno Correia')
    
    parser.add_argument(
        "-p",
        "--searchpath",
        help="Path to search for event log and registry files",
        required=False,
        default=None,
        type=str)

    parser.add_argument(
        "-l",
        "--eventlog",
        help="Event log file, or path with event log file",
        required=False,
        default=None,
        type=str)

    parser.add_argument(
        "-r",
        "--registry",
        help="Registry file, or path with registry file",
        required=False,
        default=None,
        type=str)
    
    parser.add_argument(
        "-s",
        "--startdate",
        help="Start date filter of the event log (ISOformat - YYYY-MM-DD:HH:mm:ss)",
        required=False,
        default=None,
        type=datetime.datetime.fromisoformat
    )

    parser.add_argument(
        "-e",
        "--enddate",
        help="End date filter of the event log (ISOformat - YYYY-MM-DD:HH:mm:ss)",
        required=False,
        default=None,
        type=datetime.datetime.fromisoformat
    )

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

    if args.searchpath is None and args.eventlog is None and args.registry is None:
        parser.error("at least one of the following arguments must be provided: -s/--searchpath, -l/--eventlog, -r/--registry")

    if args.searchpath is not None:
        print("-s/--searchpath argument is provided, the arguments -l/--eventlog, -r/--registry will be ignored")

        if not os.path.exists(args.searchpath):
            parser.error(f"the path {args.searchpath} does not exist")
    
    main(args)
