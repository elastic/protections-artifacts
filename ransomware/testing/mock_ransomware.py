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
                match file_ext:
                    case "gif":
                        file_header = bytes([0x47, 0x49, 0x46, 0x38])
                    case "doc":
                        file_header = bytes([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])
                    case"jpg":
                        file_header = bytes([0xff, 0xd8, 0xff])
                    case "pdf":
                        file_header = bytes([0x25, 0x50, 0x44, 0x46])
                    case "docx":
                        file_header = bytes([0x50, 0x4b])
                    case _:
                        file_header = bytes([0])
                
                fh.write(file_header)
                fh.seek(fsize)
                fh.write(bytes([0]))

    return len(os.listdir(dir_path))


def main():
    # Create target files
    cur_dir = os.path.dirname(os.path.realpath(__file__))
    target_dir = os.path.join(cur_dir, "ransomware_tmp")
    print("Create target files for ransomware")
    create_target_files(target_dir)

    mock_ransomware = os.path.join(cur_dir, "mock_ransomware.ps1")
    
    print("Running mock ransomware (single process)")
    cmd_str = "powershell.exe -ExecutionPolicy Bypass %s -path %s -delay %s" % (
        mock_ransomware,
        target_dir,
        5,
    )
    
    # Run ransomware
    print("Running {}".format(cmd_str))

    try:
        subprocess.check_call(cmd_str)
    except subprocess.CalledProcessError as e:
        print("mock_ransomware powershell subprocess did not complete")
       
if __name__ == "__main__":
    # Invoke main.
    main()
