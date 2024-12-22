import sys
import os
import hashlib
import logging
import json

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# File to store hash records
HASH_STORE_FILE = "file_hashes.json"

def save_hash_store(hash_store):
    """
    Save the hash store to the JSON file.

    :param hash_store: The dictionary containing file hashes to be saved.
    :return: None
    """
    try:
        with open(HASH_STORE_FILE,'w') as file:
            # Writing the dictionary as JSON to the file with indentation for readability
            json.dump(hash_store,file, indent=4)
    except IOError as e:
        logger.error(f"IO error while saving hash store to {HASH_STORE_FILE}: {e}")
    except PermissionError as e:
        logger.error(f"Permission error while saving hash store to {HASH_STORE_FILE}: {e}")
    except Exception as e:
        logger.error(f"Unexpected error while saving hash store: {e}")



def load_hash_store():
    """
    Load the hash store from the JSON file.

    :return: Dictionary containing the file hashes or an empty dictionary if an error occurs.
    """
    if not os.path.exists(HASH_STORE_FILE):
        # logger.warning(f"Hash store file not found: {HASH_STORE_FILE}. Returning an empty dictionary.")
        return {}

    try:
        with open(HASH_STORE_FILE,'r') as file:
            # Try loading the JSON content from the file
            hash_store = json.load(file)
            return hash_store
    except json.JSONDecodeError as e:
        logger.error(f"Error decoding JSON from {HASH_STORE_FILE}: {e}")
    except IOError as e:
        logger.error(f"IO error while opening {HASH_STORE_FILE}: {e}")
    except Exception as e:
        logger.error(f"Unexpected error while loading hash store: {e}")

    # Return an empty dictionary if any error occurs
    logger.warning(f"Returning an empty dictionary due to error in loading hash store.")
    return {}

def compute_sha256(file_path):
    """
    Reads a file and returns its SHA-256 hash as a hexadecimal string.

    :param file_path: Path to the file to be hashed.
    :return: SHA-256 hash of the file in hexadecimal format, or None if an error occurs.
    """
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as file:
            # Read the file in chunks to avoid memory issues with large files
            for chunk in iter(lambda: file.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except FileNotFoundError:
        logger.error(f"File not found: {file_path}")
    except PermissionError:
        logger.error(f"Permission denied: {file_path}")
    except Exception as e:
        logger.error(f"Unexpected error while hashing file {file_path}: {e}")
    return None


def scan_files(base_path):
    """
    Scan the given path (file or directory) and compute SHA-256 hashes for files.

    :param base_path: Path to a file or directory.
    :return: Dictionary with file paths as keys and their SHA-256 hashes as values.
    """
    files_to_hash = {}
    if os.path.isfile(base_path):
        #  calculate the hash value of this files
        hash_value = compute_sha256(base_path)
        if hash_value:
            files_to_hash[base_path] = hash_value
    elif os.path.isdir(base_path):
        # path is directory, compute the hash value for each files
        for root, _, files in os.walk(base_path):
            for file in files:
                file_path = os.path.join(root,file)
                hash_value = compute_sha256(file_path)
                if hash_value:
                    files_to_hash[file_path] = hash_value
    else:
        logging.error(f"Invalid path: {base_path}. Path is neither a file nor a directory.")
    return files_to_hash

def compare_hashes(new_hashes, stored_hashes):
    """
    Compare the new file hashes with the stored ones to identify added, modified, unchanged, and deleted files.

    :param new_hashes: Dictionary of file paths and their corresponding new hash values.
    :param stored_hashes: Dictionary of file paths and their corresponding stored hash values.
    :return: A tuple containing four dictionaries: added, modified, unchanged, and deleted.
    """

    # Initialize result dictionaries
    added = {}
    modified = {}
    unchanged = {}
    
    # Find deleted files (in stored_hashes but not in new_hashes)
    deleted = set(stored_hashes.keys()) - set(new_hashes.keys())

     # Iterate over the new hashes to check for added, modified, or unchanged files
    for file_path, new_hash in new_hashes.items():
        if file_path not in stored_hashes:
            # File is new (not in stored hashes)
            added[file_path] = new_hash
            # logger.info(f"Added: {file_path}")
        elif stored_hashes[file_path] != new_hash:
            # File hash has changed
            modified[file_path] = new_hash
            # logger.info(f"Modified: {file_path}")
        else:
            # File hash is unchanged
            unchanged[file_path] = new_hash
            # logger.info(f"Unchanged: {file_path}")
    
    # Return the results as a tuple
    return added, modified, unchanged, deleted

def main():
    if(len(sys.argv) < 2):
        logger.error("Usage: python3 file_integrity_monitor.py <path>")
        return

    base_path = sys.argv[1]

    # Validate the provided path
    if not os.path.exists(base_path):
        logger.error(f"Invalid path: {base_path}. Please provide a valid file or directory path.")
        return

    try:
        # Scan files and compute their hashes
        logging.info(f"Scanning path: {base_path}")
        new_hashes = scan_files(base_path)

        if not new_hashes:
            logger.error("No files found to process.")
            return

        # Load existing stored hashes from the hash store file
        stored_hashes = load_hash_store()

        # If there are no stored hashes, save the newly computed hashes
        if not stored_hashes:
            logger.warning("No existing hash records found. Storing new hashes.")
            save_hash_store(new_hashes)
            logger.info(f"Hash store successfully saved to {HASH_STORE_FILE}.")
        else:
            # Compare the new hashes with the stored ones and log the results
            added, modified, unchanged, deleted = compare_hashes(new_hashes, stored_hashes)


            # Log the comparison results
            logger.info("\n=== File Integrity Report ===")
            # logger.info("Added files:")
            for file, hash in added.items():
                logger.info(f"Added files: {file}")

            # logger.info("\nModified files:")
            for file, hash in modified.items():
                logger.info(f"Modified files:  {file}")

            # logger.info("\nUnchanged files:")
            for file, hash in unchanged.items():
                logger.info(f"Unchanged files:  {file}")

            # logger.info("\nDeleted files:")
            for file in deleted:
                logger.info(f"Deleted files: {file}")

            # Update the hash store with the new state
            save_hash_store(new_hashes)
            logger.info("Hash store successfully updated.")
    except Exception as e:
        logger.error(f"An error occurred during the file integrity check: {e}")
        logger.exception(e)  # Logs the full traceback for debugging
        


if __name__ == "__main__":
    main()