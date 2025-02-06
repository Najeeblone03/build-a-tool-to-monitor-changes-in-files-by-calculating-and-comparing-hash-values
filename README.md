# build-a-tool-to-monitor-changes-in-files-by-calculating-and-comparing-hash-values
COMPANY:CODE TECH IT SOLUTIONS
NAME:LONEZADA MOHAMMAD NAJEEB UL HAQ
INTERN ID:CTO8IUE
DOMAIN:CYBER SECURITY AND ETHICAL HACKING
DURATION: 4 WEEKS
MENTOR: NEELA SANTOSH

Description of the File Integrity Checker Script
The File Integrity Checker script is a Python-based utility designed to monitor and track changes in files within a specified directory. This script helps in detecting modifications, additions, and deletions of files by computing their SHA-256 hash values and comparing them with previously stored hash records. It is particularly useful in environments where file integrity needs to be ensured, such as system security, data verification, or auditing purposes.
How It WorksInitialization:
The script takes a directory path as input from the user.
It initializes the FileIntegrityChecker class, which manages file scanning and hash storage.
Hash Calculation:
The calculate_hash() method reads files in binary mode and computes their SHA-256 hash values.
It reads data in chunks of 8192 bytes to optimize performance and handle large files efficiently.
Hash Storage and Loading:
The save_hashes() method saves the computed hash values into a JSON file (file_hashes.json).
The load_hashes() method retrieves previously stored hash values, ensuring consistency across multiple script executions.
Directory Scanning:
The scan_files() method recursively scans all files in the given directory and generates a dictionary containing file paths and their corresponding hash values.
Monitoring Changes:
The monitor_changes() method compares the current file hashes with stored values.
It categorizes changes into:
Added Files: Files that exist now but were not in the previous scan.
Modified Files: Files whose content has changed (hash mismatch).
Removed Files: Files that were present in the last scan but are now missing.
The script updates the hash file after every scan to keep track of changes for future runs.
User Interaction:
If the entered directory does not exist, the script displays an error message and exits.
It prints structured output detailing the changes detected.
If no changes are found, it confirms that all files are intact.
Tools and Libraries UsedPython Standard Library Modules:
os: Used to interact with the file system and traverse directories.
hashlib: Provides secure hash functions (SHA-256) for verifying file integrity.
json: Used to store and retrieve hash values in a structured format.
Platforms for ExecutionThis script can be executed on multiple platforms, including:
Windows:
Can be run using Python in Command Prompt or PowerShell.
Requires Python to be installed and accessible from the system’s PATH.
Linux:
Compatible with all major distributions (Ubuntu, Fedora, Debian, etc.).
Can be run directly in the terminal.
macOS:
Works natively in the macOS terminal.
Requires Python3 as macOS no longer includes Python2 by default.
Potential ApplicationsSecurity Monitoring: Detect unauthorized changes in sensitive files.
Data Integrity Checks: Verify file integrity during backups and data transfers.
Auditing & Compliance: Track changes to meet regulatory requirements.
Software Development: Monitor changes in source code files in collaborative projects.
This script is a simple yet powerful tool for tracking file modifications efficiently across different operating systems.
