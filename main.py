import argparse
import read_evtx
import read_registry
from scripts.ilapfuncs import logfunc, OutputParameters, logfunc
from time import process_time, gmtime, strftime
from scripts.report import generate_report
import os
import datetime
from utils import functions as own_functions


REGISTRY_FILE = 'NTUSER.DAT'
EVTX_FILE = 'Microsoft-Windows-WebAuthN%4Operational.evtx'
SEARCH_FILES = ['*/Windows/System32/winevt/Logs/Microsoft-Windows-WebAuthN%4Operational.evtx', \
                '*/Windows/ServiceProfiles/NetworkService/NTUSER.DAT']


def main(data):
    start = process_time()

    startdate = data.startdate
    enddate = data.enddate
    search_path = data.searchpath
    output_format = data.format
    output_folder = data.output

    if output_folder:
        output_folder = os.path.abspath(data.output)
    else:
        output_folder = os.getcwd()

    out_params = OutputParameters(output_folder, output_format)
    logfunc()
    input_path = 'N\A'  # TODO

  

    terminate = [False, False] # flag to terminate if no files are found

    if search_path:
        search_path = os.path.abspath(search_path)
        exit()
        file = own_functions.search_file(SEARCH_FILES[0], search_path, True)
        print(file)
        exit()



    else:
        eventlog_file = data.eventlog
        if eventlog_file:
            eventlog_file = os.path.abspath(data.eventlog)
            if os.path.isdir(eventlog_file):
                eventlog_file = os.path.join(eventlog_file, EVTX_FILE)
                if not os.path.exists(eventlog_file):
                    logfunc(f'ERROR: File {EVTX_FILE} not found.')
                    terminate[0] = True

        registry_file = data.registry
        if registry_file:
            registry_file = os.path.abspath(data.registry)
            if os.path.isdir(registry_file):
                registry_file = os.path.join(registry_file, REGISTRY_FILE)
                if not os.path.exists(registry_file):
                    logfunc(f'ERROR: File {REGISTRY_FILE} not found.')
                    terminate[1] = True
        
    if all(terminate):
        logfunc(f'ERROR: No files to process, terminating.')
        return
    

    # ======================= File Processing =======================

    print('- ANALISADOR FORENSE PASSKEYS - ', strftime("%d/%m/%Y %H:%M:%S"))
    if data.eventlog:
        read_evtx.read_evtx_file(eventlog_file, out_params.report_folder_base, output_format, startdate, enddate)

    if data.registry:
        read_registry.read_registry_file(registry_file, out_params.report_folder_base, output_format)

    print('TERMINADO - para mais detalhes consulte os resultados na pasta de output.')
    # ======================= Terminate Report =======================

    end = process_time()
    run_time_secs = end - start
    run_time_HMS = strftime('%H:%M:%S', gmtime(run_time_secs))

    print(f'Tempo decorrido: {run_time_HMS}')

    if output_format == 'html':
        generate_report(out_params.report_folder_base, run_time_secs, run_time_HMS, input_path)


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
        choices=['csv', 'html', 'xlsx'])

    args = parser.parse_args()

    # argument validation

    if args.searchpath is None and args.eventlog is None and args.registry is None:
        parser.error("at least one of the following arguments must be provided: -s/--searchpath, -l/--eventlog, -r/--registry")

    if args.searchpath is not None:
        print("-s/--searchpath argument was provided, the arguments -l/--eventlog, -r/--registry will be ignored")

        if not os.path.exists(args.searchpath): # check if the path exists
            parser.error(f"the path {args.searchpath} does not exist")

        if not os.path.isdir(args.searchpath): # check if the path is a directory
            parser.error(f"the path {args.searchpath} does not a directory")
    
    if args.eventlog is not None:
        if not os.path.exists(args.eventlog):
            parser.error(f"the file {args.eventlog} does not exist")

    if args.registry is not None:
        if not os.path.exists(args.registry):
            parser.error(f"the file {args.registry} does not exist")

    main(args)
