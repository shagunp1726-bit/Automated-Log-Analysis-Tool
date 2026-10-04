import hashlib
import os

def calculate_hashes(file_paths):
    hashes = {}

    for file_path in file_paths:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            while True:
                data = f.read(8192)
                if not data:
                    break
                sha256.update(data)

        hashes[os.path.basename(file_path)] = sha256.hexdigest()

    return hashes
