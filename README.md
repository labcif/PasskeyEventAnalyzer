# PEA

Passkey Event Analyzer (PEA) is a tool to extract and analyze FIDO2 keys from Windows Event Logs and Registry

## Requirements

Windows 11 (Windows 10 will also work)
Python 3.11 to latest version (older versions of 3.x will also work)

## Usage

### Clone the repo

Install dependencies

```sh
pip install -r requirements.txt
```

### CLI

```sh
python py_passkey_events_analyzer.py -p <path_to_search> -l <log_file> -r <registry_file> -f <csv | html | xlsx> -o <output_folder> -s <start_date_filter> -e <end_date_filter>
```

### Examples of usage

```sh
i) Process EVTX file and dump results to EXCEL
python py_passkey_events_analyzer.py -f xlsx 
 -l PATH_TO_file_Microsoft-Windows-WebAuthN%4Operational.evtx

ii) Process EVTX file and dump results to HTML
python py_passkey_events_analyzer.py -f html 
 -l PATH_TO_file_Microsoft-Windows-WebAuthN%4Operational.evtx

iii) Process REGISTRY file "NTUSER.DAT"
 python py_passkey_events_analyzer.py -f xlsx -r NTUSER.DAT

NOTE: The registry file "NTUSER.DAT" is the one located at: 
 "c:\windows\ServiceProfiles\NetworkService\"

python py_passkey_events_analyzer.py -f xlsx -r "NTUSER.DAT"
 
iv) Process EVTX + registry files
python py_passkey_events_analyzer.py -f xlsx -r "NTUSER.DAT" 
 -l PATH_TO_file_Microsoft-Windows-WebAuthN%4Operational.evtx

v) Specify startdate and/or enddate
Options -s/--startdate date
 -s STARTDATE, --startdate STARTDATE
 -e ENDDATE / --enddate ENDDATE
DATEs format is ISO - YYYY-MM-DD:HH:mm:ss

```

# PAF

Passkey Anti Forensics is a script that erases passkey usage artifacts in Windows 11 (it should also work on Windows 10)

## Requirements

Windows 11 (Windows 10 will also work)
Python 3.11 to latest version (older versions of 3.x will also work)

## Usage

### Clone the repo

Install dependencies

```sh
pip install psutil
```

### CLI

```sh
python passkey_antiforensics.py
```
