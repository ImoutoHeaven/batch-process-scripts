import ntpath
import os
import platform


DEFAULT_LOCK_NAME = "advarchiver_comp_lock"


def get_lock_file_path(lock_name=DEFAULT_LOCK_NAME):
    if platform.system() == "Windows":
        return ntpath.join(r"C:\Windows\Temp", lock_name)
    return os.path.join("/tmp", lock_name)
