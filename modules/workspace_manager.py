import tempfile
import shutil

def create_workspace():
    return tempfile.mkdtemp(prefix="forensiclens_")

def cleanup_workspace(path):
    shutil.rmtree(path, ignore_errors=True)
