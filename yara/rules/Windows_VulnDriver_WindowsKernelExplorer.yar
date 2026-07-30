rule Windows_VulnDriver_WindowsKernelExplorer_b13403ff {
    meta:
        author = "Elastic Security"
        id = "b13403ff-5082-4694-8a56-9816b0b3d02d"
        fingerprint = "a0f108fc9b2ef84d35907c62d34ea5687890c3a26a0ab5203f644253a2e5e3f5"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Synhe Technology  Co., Ltd, Version: <= 0.0.0.0"
        threat_name = "Windows.VulnDriver.WindowsKernelExplorer"
        reference_sample = "455ff5274fbdd19ce1da6fc6725a00752761998759c6bacb9713081f613c1752"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 79 6E 68 65 20 54 65 63 68 6E 6F 6C 6F 67 79 20 20 43 6F 2E 2C 20 4C 74 64 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 57 00 69 00 6E 00 64 00 6F 00 77 00 73 00 4B 00 65 00 72 00 6E 00 65 00 6C 00 45 00 78 00 70 00 6C 00 6F 00 72 00 65 00 72 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}[\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00]/
        $str1 = "Windows Kernel Explorer" wide
        $str2 = "Windows Kernel Explorer Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2
}

