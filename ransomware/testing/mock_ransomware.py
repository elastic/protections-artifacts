import os
import random
import shutil
import string
import subprocess


def get_random_string(length=10):
    return "".join(random.choice(string.ascii_lowercase) for _ in range(length))


def handle_remote_readonly(func, path, exc_info):
    import stat

    if not os.access(path, os.W_OK):

        # Is the error an access error ?
        os.chmod(path, stat.S_IWUSR)
        func(path)
    else:
        raise


def create_target_files(dir_path, num_set=15, fsize=100000):
    if os.path.isdir(dir_path):
        shutil.rmtree(dir_path, onerror=handle_remote_readonly)
    os.makedirs(dir_path)

    for _ in range(num_set):
        for file_ext in ["gif", "doc", "jpg", "pdf", "docx", "txt"]:
            file_path = os.path.join(
                dir_path, "%s.%s" % (get_random_string(), file_ext)
            )
            print(f"Creating {file_path} for size = {fsize} bytes")
            with open(file_path, "wb") as fh:
                fh.write(os.urandom(fsize))

    return len(os.listdir(dir_path))


def main():
    # Create target files
    cur_dir = os.path.dirname(os.path.realpath(__file__))
    target_dir = os.path.join(cur_dir, "ransomware_tmp")
    print("Create target files for ransomware")
    create_target_files(target_dir)

    mock_ransomware = os.path.join(cur_dir, "mock_ransomware.ps1")

    print("Running mock ransomware (single process")
    cmd_str = "powershell.exe -ExecutionPolicy Bypass %s -path %s -delay %s" % (
        mock_ransomware,
        target_dir,
        5,
    )

    # Run ransomware
    print("Running {}".format(cmd_str))
    subprocess.check_call(cmd_str)


if __name__ == "__main__":
    # Invoke main.
    main()
