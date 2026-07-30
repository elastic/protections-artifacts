rule Windows_VulnDriver_Rootkit_5b1586ea {
    meta:
        author = "Elastic Security"
        id = "5b1586ea-be99-4f4d-9546-9bda43748fe1"
        fingerprint = "226f51f3a5280b428c5341802c9c35c884809e0a950c3ed65fa5b99ceb6a14ab"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Beijing JoinHope Image Technology Ltd., Version: <= 2022.10.11.926"
        threat_name = "Windows.VulnDriver.Rootkit"
        reference_sample = "24c900024d213549502301c366d18c318887630f04c96bf0a3d6ba74e0df164f"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 42 65 69 6A 69 6E 67 20 4A 6F 69 6E 48 6F 70 65 20 49 6D 61 67 65 20 54 65 63 68 6E 6F 6C 6F 67 79 20 4C 74 64 2E }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x06]|[\x00-\xe5][\x07-\x07])[\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x09][\x00-\x00][\xe6-\xe6][\x07-\x07][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x0a-\x0a][\x00-\x00][\xe6-\xe6][\x07-\x07][\x00-\xff][\x00-\xff][\x00-\x0a][\x00-\x00]|[\x0a-\x0a][\x00-\x00][\xe6-\xe6][\x07-\x07]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x02]|[\x00-\x9d][\x03-\x03])[\x0b-\x0b][\x00-\x00]|[\x0a-\x0a][\x00-\x00][\xe6-\xe6][\x07-\x07][\x9e-\x9e][\x03-\x03][\x0b-\x0b][\x00-\x00])/
        $str1 = "FilDriverx64.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1
}

rule Windows_VulnDriver_Rootkit_e94ca533 {
    meta:
        author = "Elastic Security"
        id = "e94ca533-1e27-44a6-b8ff-092d47a168db"
        fingerprint = "df111196f95a01031f22cbefa3bde2d6d89f5c99ec31e53d8513e875415a6be3"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: 湖南蓝途方鼎科技有限公司"
        threat_name = "Windows.VulnDriver.Rootkit"
        reference_sample = "7a84703552ae032a0d1699a081e422ed6c958bbe56d5b41839c8bfa6395bee1d"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] E6 B9 96 E5 8D 97 E8 93 9D E9 80 94 E6 96 B9 E9 BC 8E E7 A7 91 E6 8A 80 E6 9C 89 E9 99 90 E5 85 AC E5 8F B8 }
        $str1 = "RedDriver.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

rule Windows_VulnDriver_Rootkit_aa10c0ad {
    meta:
        author = "Elastic Security"
        id = "aa10c0ad-de61-4a47-bdbe-f232e4e383e2"
        fingerprint = "e8da953d36cd407c1e56e89f50609f2a66c507d5900a1205ce6f25c7be1345ce"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Zhuhai liancheng Technology Co., Ltd."
        threat_name = "Windows.VulnDriver.Rootkit"
        reference_sample = "0440ef40c46fdd2b5d86e7feef8577a8591de862cfd7928cdbcc8f47b8fa3ffc"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 5A 68 75 68 61 69 20 6C 69 61 6E 63 68 65 6E 67 20 54 65 63 68 6E 6F 6C 6F 67 79 20 43 6F 2E 2C 20 4C 74 64 2E }
        $str1 = "KApcHelper.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

rule Windows_VulnDriver_Rootkit_dc7b1255 {
    meta:
        author = "Elastic Security"
        id = "dc7b1255-513d-4e8a-9dd1-1903a931d32a"
        fingerprint = "acf2f2b7ed2fbc2be6152cf5476253db65cb821ceeef209d1dcfc01c7a0ecf0e"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Beijing Founder Apabi Technology Limited"
        threat_name = "Windows.VulnDriver.Rootkit"
        reference_sample = "df72cb33a23ae8f6f9dc64bb738fcfaea959368ce05cf399f3c7db5e90104bd7"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 42 65 69 6A 69 6E 67 20 46 6F 75 6E 64 65 72 20 41 70 61 62 69 20 54 65 63 68 6E 6F 6C 6F 67 79 20 4C 69 6D 69 74 65 64 }
        $str1 = "MDriver.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

rule Windows_VulnDriver_Rootkit_6a1fb6e5 {
    meta:
        author = "Elastic Security"
        id = "6a1fb6e5-dcfa-4b83-9e43-aeb2f82076cd"
        fingerprint = "d01e5958846990428a8f8dfd15fcc6a53c978be74b3dc208d121b948fe5dd4b9"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: 重庆貔赑貅软件科技工作室 (王真)"
        threat_name = "Windows.VulnDriver.Rootkit"
        reference_sample = "f154167b4b92851f478b3c3f88423cd719e3139bac5da07f33dd7929796c96f5"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] E9 87 8D E5 BA 86 E8 B2 94 E8 B5 91 E8 B2 85 E8 BD AF E4 BB B6 E7 A7 91 E6 8A 80 E5 B7 A5 E4 BD 9C E5 AE A4 20 28 E7 8E 8B E7 9C 9F 29 }
        $str1 = "project-ioctl.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

rule Windows_VulnDriver_Rootkit_06e4d47e {
    meta:
        author = "Elastic Security"
        id = "06e4d47e-8db9-4e95-9fea-b13e9666c646"
        fingerprint = "6efa09308a4142a11b89e243258cd9192768e7c030b64cb4fad797ff4861c1ea"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: WDKTestCert anash,133231280654008727"
        threat_name = "Windows.VulnDriver.Rootkit"
        reference_sample = "0ae8d1dd56a8a000ced74a627052933d2e9bff31d251de185b3c0c5fc94a44db"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 57 44 4B 54 65 73 74 43 65 72 74 20 61 6E 61 73 68 2C 31 33 33 32 33 31 32 38 30 36 35 34 30 30 38 37 32 37 }
        $str1 = "Chaos-Rootkit.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

rule Windows_VulnDriver_Rootkit_d141ff75 {
    meta:
        author = "Elastic Security"
        id = "d141ff75-6ffe-4cae-b839-cdbbfe74bfe4"
        fingerprint = "283e528a24c138af82ea527a8dd8c132aa2ef340d84e316adb482b224297cd30"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: WDKTestCert zezec,132961360795713868"
        threat_name = "Windows.VulnDriver.Rootkit"
        reference_sample = "23e89fd30a1c7db37f3ea81b779ce9acf8a4294397cbb54cff350d54afcfd931"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 57 44 4B 54 65 73 74 43 65 72 74 20 7A 65 7A 65 63 2C 31 33 32 39 36 31 33 36 30 37 39 35 37 31 33 38 36 38 }
        $str1 = "Malicious.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

rule Windows_VulnDriver_Rootkit_fbced6b4 {
    meta:
        author = "Elastic Security"
        id = "fbced6b4-b858-4f9e-90c2-a244e08bbe74"
        fingerprint = "e88bc5ec4c2927be7d150762e71de8861870f240bd948fe1484165c27aed1214"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Hunan Goldmind Education Equipment Co., Ltd., Version: <= 3.0.0.0"
        threat_name = "Windows.VulnDriver.Rootkit"
        reference_sample = "06cc1ce9a1d413b2ba156adcb8e9d398cba4027de1b7b98e1c2fe49e54193c70"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 48 75 6E 61 6E 20 47 6F 6C 64 6D 69 6E 64 20 45 64 75 63 61 74 69 6F 6E 20 45 71 75 69 70 6D 65 6E 74 20 43 6F 2E 2C 20 4C 74 64 2E }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "Driver.pdb"
        $str2 = "Low-Level Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1 and $str2
}

