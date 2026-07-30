rule Windows_VulnDriver_Samsung_43cc9191 {
    meta:
        author = "Elastic Security"
        id = "43cc9191-b87b-452f-b0d1-0da411bfc218"
        fingerprint = "e360b28a8590fe4c25b4e5e6eb2fdbe09d563f26d2c86bc7a9c4c67edbfae79d"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Samsung Electronics CO., LTD., Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.Samsung"
        reference_sample = "09e863170e546b5889ad02f1effecf6ec8ea0a99d02878548c0415e460618c88"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 61 6D 73 75 6E 67 20 45 6C 65 63 74 72 6F 6E 69 63 73 20 43 4F 2E 2C 20 4C 54 44 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 53 00 53 00 50 00 4F 00 52 00 54 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "SSPORT.pdb"
        $str2 = "Port Contention Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Samsung_660fca86 {
    meta:
        author = "Elastic Security"
        id = "660fca86-552f-4701-8e0e-d745ac1aab34"
        fingerprint = "6510dfe2a9bb9f8645ecd5d9aa5617c5466fcfd62952993ad70da509b39527ef"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Samsung Electronics CO., LTD., Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.Samsung"
        reference_sample = "1e24c45ce2672ee403db34077c88e8b7d7797d113c6fd161906dce3784da627d"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 61 6D 73 75 6E 67 20 45 6C 65 63 74 72 6F 6E 69 63 73 20 43 4F 2E 2C 20 4C 54 44 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 53 00 42 00 49 00 4F 00 53 00 49 00 4F 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "SBIOSIO32.pdb"
        $str2 = "IOCTL_IO_WRITE_PORT"
        $str3 = "IOCTL_IO_READ_PORT"
        $str4 = "Samsung (R) BIOS IO driver" wide
        $str5 = "SBIOSIO Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4 and $str5
}

rule Windows_VulnDriver_Samsung_2cfc2565 {
    meta:
        author = "Elastic Security"
        id = "2cfc2565-07d6-460f-a5ea-e5d53bf9b424"
        fingerprint = "389bbc6e292183a409ce78fd5ff1cb6b711c49360ec422de073a6c0561e6953c"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Samsung Electronics CO., LTD., Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.Samsung"
        reference_sample = "39336e2ce105901ab65021d6fdc3932d3d6aab665fe4bd55aa1aa66eb0de32f0"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 61 6D 73 75 6E 67 20 45 6C 65 63 74 72 6F 6E 69 63 73 20 43 4F 2E 2C 20 4C 54 44 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 53 00 42 00 49 00 4F 00 53 00 49 00 4F 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "SBIOSIO64.pdb"
        $str2 = "IOCTL_IO_WRITE_PORT"
        $str3 = "IOCTL_IO_READ_PORT"
        $str4 = "Samsung (R) BIOS IO driver" wide
        $str5 = "SBIOSIO Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4 and $str5
}

rule Windows_VulnDriver_Samsung_4c642da2 {
    meta:
        author = "Elastic Security"
        id = "4c642da2-171b-43cf-ae24-65e4e39a3d7b"
        fingerprint = "15652c23ca02de24ce3955dc9820405d032431436a9c498f49387d402a3479ed"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Samsung Electronics Co., Ltd."
        threat_name = "Windows.VulnDriver.Samsung"
        reference_sample = "be54f7279e69fb7651f98e91d24069dbc7c4c67e65850e486622ccbdc44d9a57"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 61 6D 73 75 6E 67 20 45 6C 65 63 74 72 6F 6E 69 63 73 20 43 6F 2E 2C 20 4C 74 64 2E }
        $str1 = "IOCTL_MAGICIAN_GET_AHCI_CONTROLLER_SATA_MODE"
        $str2 = "IOCTL_MAGICIAN_GET_AHCI_PORT_SATA_MODE"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2
}

