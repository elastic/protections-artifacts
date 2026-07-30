rule Windows_VulnDriver_SecurStar_35bd6206 {
    meta:
        author = "Elastic Security"
        id = "35bd6206-ee9a-4702-a5bf-0932ecb6900e"
        fingerprint = "eea650b32e60eae9b5266dd9eae0cda2224746a6b24dab9f4f6c70e904e92a6a"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: SecurStar GmbH"
        threat_name = "Windows.VulnDriver.SecurStar"
        reference_sample = "3c6f9917418e991ed41540d8d882c8ca51d582a82fd01bff6cdf26591454faf5"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 65 63 75 72 53 74 61 72 20 47 6D 62 48 }
        $str1 = "Dcr.pdb"
        $str2 = "IOCTL_STORAGE_GET_DEVICE_NUMBER"
        $str3 = "IOCTL_VOLUME_ONLINE"
        $str4 = "\\Device\\KeyboardClass"
        $str5 = "\\Device\\MountPointManager"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2 and $str3 and $str4 and $str5
}

