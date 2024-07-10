# PEA

Passkey Event Analyzer is a tool to extract and analyze FIDO2 keys from Windows Event Logs and Registry

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
python main.py -p <path_to_search> -l <log_file> -r <registry_file> -f <csv | html | xlsx> -o <output_folder> -s <start_date_filter> -e <end_date_filter>
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