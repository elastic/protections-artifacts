rule Windows_VulnDriver_Kingsoft_73226a0b {
    meta:
        author = "Elastic Security"
        id = "73226a0b-9362-47ce-934b-663d9a52f8aa"
        fingerprint = "e47f00a11660ea2b3fd30e07c104cddb62a734d2b6fa28c4f91bafdd62d8e81d"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Beijing Kingsoft Security software Co.,Ltd, Version: <= 9.2.707.1214"
        threat_name = "Windows.VulnDriver.Kingsoft"
        reference_sample = "08eb2d2aa25c5f0af4e72a7e0126735536f6c2c05e9c7437282171afe5e322c6"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 42 65 69 6A 69 6E 67 20 4B 69 6E 67 73 6F 66 74 20 53 65 63 75 72 69 74 79 20 73 6F 66 74 77 61 72 65 20 43 6F 2E 2C 4C 74 64 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6D 00 79 00 64 00 72 00 69 00 76 00 65 00 72 00 73 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x08][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x01][\x00-\x00][\x09-\x09][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x09-\x09][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x01]|[\x00-\xc2][\x02-\x02])|[\x02-\x02][\x00-\x00][\x09-\x09][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x03]|[\x00-\xbd][\x04-\x04])[\xc3-\xc3][\x02-\x02]|[\x02-\x02][\x00-\x00][\x09-\x09][\x00-\x00][\xbe-\xbe][\x04-\x04][\xc3-\xc3][\x02-\x02])/
        $str1 = "MyDrivers.pdb"
        $str2 = "DriverGenius" wide
        $str3 = "DriverGenius Hardware monitor" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Kingsoft_0abfdb7c {
    meta:
        author = "Elastic Security"
        id = "0abfdb7c-7580-4efe-93c0-e8785ac1c484"
        fingerprint = "29c4f8ada15d47e08bcb1a0a795fca7b5bec6467f7e3c0ae91a064008318174b"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Beijing Kingsoft Security software Co.,Ltd, Version: <= 2017.12.6.132"
        threat_name = "Windows.VulnDriver.Kingsoft"
        reference_sample = "26ed45461e62d733f33671bfd0724399d866ee7606f3f112c90896ce8355392e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 42 65 69 6A 69 6E 67 20 4B 69 6E 67 73 6F 66 74 20 53 65 63 75 72 69 74 79 20 73 6F 66 74 77 61 72 65 20 43 6F 2E 2C 4C 74 64 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6B 00 73 00 61 00 70 00 69 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x06]|[\x00-\xe0][\x07-\x07])[\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x0b][\x00-\x00][\xe1-\xe1][\x07-\x07][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x0c-\x0c][\x00-\x00][\xe1-\xe1][\x07-\x07][\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00]|[\x0c-\x0c][\x00-\x00][\xe1-\xe1][\x07-\x07][\x00-\x83][\x00-\x00][\x06-\x06][\x00-\x00]|[\x0c-\x0c][\x00-\x00][\xe1-\xe1][\x07-\x07][\x84-\x84][\x00-\x00][\x06-\x06][\x00-\x00])/
        $str1 = "ksapi64.pdb"
        $str2 = "Kingsoft Antivirus Security System" wide
        $str3 = "Kingsoft KSAPI Module" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Kingsoft_cd63a34b {
    meta:
        author = "Elastic Security"
        id = "cd63a34b-7839-4c56-84b4-5bf76fb6fae9"
        fingerprint = "b0936e01ae69b89d06b3d866335785d6f2eaafc0f1ad8f11ce3b52b400704f4d"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Beijing Kingsoft Security software Co.,Ltd, Version: <= 2017.7.3.367"
        threat_name = "Windows.VulnDriver.Kingsoft"
        reference_sample = "597eff2718073b11da3d4bcade9a03fb4684f9be57d184fce65ac70a2ef07246"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 42 65 69 6A 69 6E 67 20 4B 69 6E 67 73 6F 66 74 20 53 65 63 75 72 69 74 79 20 73 6F 66 74 77 61 72 65 20 43 6F 2E 2C 4C 74 64 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6B 00 74 00 64 00 69 00 66 00 69 00 6C 00 74 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x06]|[\x00-\xe0][\x07-\x07])[\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x06][\x00-\x00][\xe1-\xe1][\x07-\x07][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x07-\x07][\x00-\x00][\xe1-\xe1][\x07-\x07][\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00]|[\x07-\x07][\x00-\x00][\xe1-\xe1][\x07-\x07]([\x00-\xff][\x00-\x00]|[\x00-\x6e][\x01-\x01])[\x03-\x03][\x00-\x00]|[\x07-\x07][\x00-\x00][\xe1-\xe1][\x07-\x07][\x6f-\x6f][\x01-\x01][\x03-\x03][\x00-\x00])/
        $str1 = "kdhacker64.pdb"
        $str2 = "Kingsoft Internet Security" wide
        $str3 = "Kingsoft Firewall TdiFilter Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

