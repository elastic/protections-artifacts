rule Windows_VulnDriver_Fileseclab_4a21229a {
    meta:
        author = "Elastic Security"
        id = "4a21229a-8847-4909-b3cd-69b4078a4825"
        fingerprint = "dcbdbd375bae3d9206a82bbffa9f803492ed9588333075d93fad4b9f3261be7b"
        creation_date = "2024-03-05"
        last_modified = "2024-09-30"
        threat_name = "Windows.VulnDriver.Fileseclab"
        reference_sample = "ae55a0e93e5ef3948adecf20fa55b0f555dcf40589917a5bfbaa732075f0cc12"
        severity = 100
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "filwfp.sys"
        $a2 = "filnk.sys"
        $a3 = { 5C 00 64 00 65 00 76 00 69 00 63 00 65 00 5C 00 66 00 69 00 6C 00 77 00 66 00 70 00 }
        $a4 = { 5C 00 64 00 65 00 76 00 69 00 63 00 65 00 5C 00 66 00 69 00 6C 00 77 00 66 00 70 00 }
        $b1 = { 31 00 2C 00 20 00 30 00 2C 00 20 00 30 00 2C 00 20 00 }
        $b2 = { 32 00 2C 00 20 00 30 00 2C 00 20 00 30 00 2C 00 20 00 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and 1 of ($a*) and 1 of ($b*)
}

rule Windows_VulnDriver_Fileseclab_28a4b7f3 {
    meta:
        author = "Elastic Security"
        id = "28a4b7f3-89a9-4f45-9ad5-3d38cab27f2f"
        fingerprint = "8247a0fb04ea0e0676468818f25b89c7e083965bdd50220c6068bf46cc03d63f"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Name: fildds.sys, Version: <= 2.0.0.8553"
        threat_name = "Windows.VulnDriver.Fileseclab"
        reference_sample = "034bcc75781a525e44f57ba149fe8b51c7124da87f6ed25a6da585805dcf1f6f"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 66 00 69 00 6C 00 64 00 64 00 73 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x20]|[\x00-\x68][\x21-\x21])[\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x69-\x69][\x21-\x21][\x00-\x00][\x00-\x00])/
        $str1 = "Filseclab Dynamic Defense System" wide
        $str2 = "Filseclab Dynamic Defense System Drv" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Fileseclab_6a3e77b1 {
    meta:
        author = "Elastic Security"
        id = "6a3e77b1-930e-4383-8e27-7959ed7afbfa"
        fingerprint = "04140a16298fe3aa6d80c1b70ec2b168d85b82e06a6cf47894027665d94669d4"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Filseclab Corporation, Version: <= 1.0.0.1216"
        threat_name = "Windows.VulnDriver.Fileseclab"
        reference_sample = "490cfbb540dcd70b7bff4fdd62e7ed7400bbfebaf5083523d49f7184670f7b9a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 46 69 6C 73 65 63 6C 61 62 20 43 6F 72 70 6F 72 61 74 69 6F 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 66 00 69 00 6C 00 77 00 66 00 70 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x03]|[\x00-\xbf][\x04-\x04])[\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\xc0-\xc0][\x04-\x04][\x00-\x00][\x00-\x00])/
        $str1 = "filwfp.pdb"
        $str2 = "Filseclab Firewall" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

