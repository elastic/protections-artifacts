rule Windows_VulnDriver_K7RKScan_5961a62d {
    meta:
        author = "Elastic Security"
        id = "5961a62d-fe45-4f64-b2c1-bce314128a15"
        fingerprint = "2b629e57ecf515c1ed002ce51e96e9e19c98430580f84fa84978bf4e2cc755f7"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher, Version: <= 23.0.0.10"
        threat_name = "Windows.VulnDriver.K7RKScan"
        reference_sample = "1ad0c870620b8a749217600c8f68558da355e1ba0a8e91cb758d8418beb13196"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4B 00 37 00 52 00 4B 00 53 00 63 00 61 00 6E 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x16][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x17-\x17][\x00-\x00][\x00-\x09][\x00-\x00][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x17-\x17][\x00-\x00][\x0a-\x0a][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "K7RKScan.pdb"
        $str2 = "K7RKScan" wide
        $str3 = "K7RKScan Kernel Module" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_K7RKScan_70dced43 {
    meta:
        author = "Elastic Security"
        id = "70dced43-a2d7-4452-9d95-17a035c4fec0"
        fingerprint = "3c0c2fd1de9b32dd95d5d40352ad9d7e9ed4749a6182d32e185ea3cabbdce0ac"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Name: K7RKScan, Version: <= 15.1.0.6"
        threat_name = "Windows.VulnDriver.K7RKScan"
        reference_sample = "6004076ac3e43b0640e4d9e817c0a437e224a1c9813bbf61a9c47b7817cb2aa9"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4B 00 37 00 52 00 4B 00 53 00 63 00 61 00 6E 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x0e][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x0f-\x0f][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x0f-\x0f][\x00-\x00][\x00-\x05][\x00-\x00][\x00-\x00][\x00-\x00]|[\x01-\x01][\x00-\x00][\x0f-\x0f][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "K7RKScan.pdb"
        $str2 = "K7RKScan" wide
        $str3 = "K7RKScan Kernel Module" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_K7RKScan_4515e9a4 {
    meta:
        author = "Elastic Security"
        id = "4515e9a4-6222-4368-934a-32e173de11d3"
        fingerprint = "63f153cd4dbe200ea8b42318d7b820a6bcc53325895f9d66bc1ccbd5f238d9b7"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Binzhoushi Yongyu Feed Co.,LTd., Version: <= 23.0.0.10"
        threat_name = "Windows.VulnDriver.K7RKScan"
        reference_sample = "b5c2a3fbce455507cc6c11475e69b7333c3823c89e5f5e05493eee2214b24071"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 42 69 6E 7A 68 6F 75 73 68 69 20 59 6F 6E 67 79 75 20 46 65 65 64 20 43 6F 2E 2C 4C 54 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4B 00 37 00 52 00 4B 00 53 00 63 00 61 00 6E 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x16][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x17-\x17][\x00-\x00][\x00-\x09][\x00-\x00][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x17-\x17][\x00-\x00][\x0a-\x0a][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "K7RKScan.pdb"
        $str2 = "K7RKScan" wide
        $str3 = "K7RKScan Kernel Module" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

