import hashlib

def compute_hashes(file_path):
    md5 = hashlib.md5()
    sha = hashlib.sha256()

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            md5.update(chunk)
            sha.update(chunk)

    return {
        "md5": md5.hexdigest(),
        "sha256": sha.hexdigest()
    }