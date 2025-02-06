import os
import hashlib
import json

class FileIntegrityChecker:
    """
    A class to monitor file integrity by tracking changes in file hashes within a directory.
    Useful for detecting modifications, additions, and deletions of files.
    """

    def __init__(self, directory, hash_file="file_hashes.json"):
        """
        Initializes the FileIntegrityChecker.

        :param directory: The directory to monitor.
        :param hash_file: The file to store hash values.
        """
        self.directory = directory
        self.hash_file = hash_file
        self.file_hashes = {}
        self.load_hashes()

    def calculate_hash(self, file_path):
        """
        Calculates the SHA-256 hash of a file.

        :param file_path: Path to the file.
        :return: The hash value as a hexadecimal string.
        """
        sha256 = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                while chunk := f.read(8192):  # Read in chunks for efficiency
                    sha256.update(chunk)
            return sha256.hexdigest()
        except (OSError, IOError) as e:
            print(f"Error reading file: {file_path} -> {e}")
            return None

    def load_hashes(self):
        """
        Loads previously stored hash values from a JSON file.
        Ensures data persistence between runs.
        """
        if os.path.exists(self.hash_file):
            try:
                with open(self.hash_file, "r") as f:
                    self.file_hashes = json.load(f)
            except (OSError, IOError, json.JSONDecodeError) as e:
                print(f"Warning: Unable to load previous hash data. Proceeding with fresh scan. ({e})")

    def save_hashes(self):
        """
        Saves the current hash values to a JSON file.
        This allows future comparisons to detect changes.
        """
        try:
            with open(self.hash_file, "w") as f:
                json.dump(self.file_hashes, f, indent=4)
        except (OSError, IOError) as e:
            print(f"Error saving hash data: {e}")

    def scan_files(self):
        """
        Scans the directory for files and calculates their hash values.

        :return: A dictionary of file paths and their hash values.
        """
        updated_hashes = {}
        for root, _, files in os.walk(self.directory):
            for file in files:
                file_path = os.path.join(root, file)
                file_hash = self.calculate_hash(file_path)
                if file_hash:
                    updated_hashes[file_path] = file_hash
        return updated_hashes

    def monitor_changes(self):
        """
        Compares current file hashes with stored hashes and identifies changes.

        :return: A dictionary with added, modified, and removed files.
        """
        current_hashes = self.scan_files()
        added, modified, removed = {}, {}, []

        # Identify added and modified files
        for file_path, file_hash in current_hashes.items():
            if file_path not in self.file_hashes:
                added[file_path] = file_hash
            elif self.file_hashes[file_path] != file_hash:
                modified[file_path] = file_hash

        # Identify removed files
        for file_path in self.file_hashes.keys():
            if file_path not in current_hashes:
                removed.append(file_path)

        # Update stored hashes
        self.file_hashes = current_hashes
        self.save_hashes()

        return {
            "added": added,
            "modified": modified,
            "removed": removed
        }

if __name__ == "__main__":
    directory_to_monitor = input("Enter the directory to monitor: ").strip()

    if not os.path.isdir(directory_to_monitor):
        print("Error: The specified directory does not exist. Please enter a valid path.")
    else:
        checker = FileIntegrityChecker(directory_to_monitor)
        print("\nScanning for changes...")

        changes = checker.monitor_changes()

        # Display detected changes in a structured way
        print("\n--- Changes Detected ---")
        if changes["added"]:
            print("\n🔹 Newly Added Files:")
            for file in changes["added"]:
                print(f"   + {file}")

        if changes["modified"]:
            print("\n✏️  Modified Files:")
            for file in changes["modified"]:
                print(f"   ~ {file}")

        if changes["removed"]:
            print("\n🗑️  Removed Files:")
            for file in changes["removed"]:
                print(f"   - {file}")

        if not (changes["added"] or changes["modified"] or changes["removed"]):
            print("\n✅ No changes detected. All files are intact.")
