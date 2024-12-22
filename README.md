# File Integrity Monitor

This is a Python-based script to monitor the integrity of files and directories by computing their SHA-256 hashes. The script compares the newly calculated hashes of files with the stored ones to detect any changes, additions, deletions, or modifications in the files.

## Features
- **Scan Files and Directories**: The script can scan a given file or directory, calculating the SHA-256 hash for each file.
- **Track File Integrity**: It compares the current file hashes to a previously stored record to detect any changes.
- **Generate Reports**: It generates a file integrity report, showing added, modified, unchanged, and deleted files.
- **Persistent Storage**: The hashes are stored in a `JSON` file, which is updated after every scan to maintain the integrity check state.

## Requirements
- Python 3.x
- Required Python modules:
  - `hashlib`
  - `os`
  - `logging`
  - `json`

## Installation

### 1. **Clone the Repository**

First, clone this repository to your local machine:

```bash
git clone https://github.com/your-username/file-integrity-monitor.git
```

### 2. **Run the Script**

You can run the script by executing it from the command line, passing the path of the file or directory you want to monitor:

```bash
python3 file_integrity_monitor.py <path_to_directory_or_file>
```
For example, if you want to scan a directory /path/to/your/files, run the following command:

```bash
python3 file_integrity_monitor.py /path/to/your/files
```

## Project Page

You can find the project at: [File Integrity Monitoring](https://roadmap.sh/projects/file-integrity-checker)

