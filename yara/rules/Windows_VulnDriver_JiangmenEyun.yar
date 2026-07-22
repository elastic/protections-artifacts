rule Windows_VulnDriver_JiangmenEyun_6a5001dc {
    meta:
        author = "Elastic Security"
        id = "6a5001dc-5d8a-408b-a2dd-91daad1b5f75"
        fingerprint = "c36faa7608823027464d95113707586ba4a6d8393ab22f4965d88d084a5951b1"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Jiangmen Eyun Network Co., Ltd., Version: <= 1.2.0.0"
        threat_name = "Windows.VulnDriver.JiangmenEyun"
        reference_sample = "1698ba7eeee6ff9272cc25b242af89190ff23fd9530f21aa8f0f3792412594f3"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4A 69 61 6E 67 6D 65 6E 20 45 79 75 6E 20 4E 65 74 77 6F 72 6B 20 43 6F 2E 2C 20 4C 74 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 44 00 63 00 50 00 72 00 6F 00 74 00 65 00 63 00 74 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "DcProtect.pdb"
        $str2 = "DcProtect (R) Win7x64 driver " wide
        $str3 = "DcProtect Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_JiangmenEyun_17ad9357 {
    meta:
        author = "Elastic Security"
        id = "17ad9357-6151-4a9c-8504-e67c5647c5a3"
        fingerprint = "349e349837b0e9b736392b6a4049ff084aef5cb0004029ccbd9c65180c1e8bb2"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Jiangmen Eyun Network Co., Ltd., Version: <= 1.2.0.0"
        threat_name = "Windows.VulnDriver.JiangmenEyun"
        reference_sample = "3af9c376d43321e813057ecd0403e71cafc3302139e2409ab41e254386c33ecb"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4A 69 61 6E 67 6D 65 6E 20 45 79 75 6E 20 4E 65 74 77 6F 72 6B 20 43 6F 2E 2C 20 4C 74 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 44 00 63 00 50 00 72 00 6F 00 74 00 65 00 63 00 74 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "DcProtect.pdb"
        $str2 = "DcProtect (R) Win10x86 driver " wide
        $str3 = "DcProtect Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_JiangmenEyun_7b57dd2d {
    meta:
        author = "Elastic Security"
        id = "7b57dd2d-fe7f-4e33-be0e-6dbe78ff5fb8"
        fingerprint = "fb605ba2c8c48284faca8a7c0f0096c3effe8d46169ecd76270390319904aa90"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Jiangmen Eyun Network Co., Ltd., Version: <= 1.2.0.0"
        threat_name = "Windows.VulnDriver.JiangmenEyun"
        reference_sample = "55b5bcbf8fb4e1ce99d201d3903d785888c928aa26e947ce2cdb99eefd0dae03"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4A 69 61 6E 67 6D 65 6E 20 45 79 75 6E 20 4E 65 74 77 6F 72 6B 20 43 6F 2E 2C 20 4C 74 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 44 00 63 00 50 00 72 00 6F 00 74 00 65 00 63 00 74 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "DcProtect.pdb"
        $str2 = "DcProtect (R) Win7x86 driver " wide
        $str3 = "DcProtect Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_JiangmenEyun_8374b819 {
    meta:
        author = "Elastic Security"
        id = "8374b819-b0f5-4e78-88ca-014f4bdb2412"
        fingerprint = "8ef1f89c9363ce0ff4526ad3fa7432c7563e693fdd4d10c06db5f8bfa859bac5"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Jiangmen Eyun Network Co., Ltd., Version: <= 1.2.0.0"
        threat_name = "Windows.VulnDriver.JiangmenEyun"
        reference_sample = "b2247e68386c1bdfd48687105c3728ebbad672daffa91b57845b4e49693ffd71"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4A 69 61 6E 67 6D 65 6E 20 45 79 75 6E 20 4E 65 74 77 6F 72 6B 20 43 6F 2E 2C 20 4C 74 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 44 00 63 00 50 00 72 00 6F 00 74 00 65 00 63 00 74 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "DcProtect.pdb"
        $str2 = "DcProtect (R) Win10x64 driver " wide
        $str3 = "DcProtect Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_JiangmenEyun_205aa263 {
    meta:
        author = "Elastic Security"
        id = "205aa263-ac5a-48f0-8b1d-5ce10ebae3f9"
        fingerprint = "125e6b4691cab29a5564927d404c63fc40b2b3d42869ae086daad7b082075240"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Jiangmen Eyun Network Co., Ltd., Version: <= 1.2.0.0"
        threat_name = "Windows.VulnDriver.JiangmenEyun"
        reference_sample = "c35cab244bd88bf0b1e7fc89c587d82763f66cf1108084713f867f72cc6f3633"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4A 69 61 6E 67 6D 65 6E 20 45 79 75 6E 20 4E 65 74 77 6F 72 6B 20 43 6F 2E 2C 20 4C 74 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 44 00 63 00 50 00 72 00 6F 00 74 00 65 00 63 00 74 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "DcProtect.pdb"
        $str2 = "DcProtect (R) Win8x86 driver " wide
        $str3 = "DcProtect Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_JiangmenEyun_719b7eb4 {
    meta:
        author = "Elastic Security"
        id = "719b7eb4-d3b4-46b1-8e99-6bdebed04286"
        fingerprint = "6687252311c07c7aaf459e22b823a73f5c68b5aaea69d5195072551b47310661"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Jiangmen Eyun Network Co., Ltd., Version: <= 1.2.0.0"
        threat_name = "Windows.VulnDriver.JiangmenEyun"
        reference_sample = "f8d45fa03f56e2ea14920b902856666b8d44f1f1b16644baf8c1ae9a61851fb6"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4A 69 61 6E 67 6D 65 6E 20 45 79 75 6E 20 4E 65 74 77 6F 72 6B 20 43 6F 2E 2C 20 4C 74 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 44 00 63 00 50 00 72 00 6F 00 74 00 65 00 63 00 74 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "DcProtect.pdb"
        $str2 = "DcProtect (R) Win8x64 driver " wide
        $str3 = "DcProtect Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_JiangmenEyun_7c140a29 {
    meta:
        author = "Elastic Security"
        id = "7c140a29-440a-4930-877b-101379fd9e96"
        fingerprint = "7538a4e0b2e3575c6180745b6681f5caaa9d8b9abad8cc256cbb0d745f09b023"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Jiangmen Eyun Network Co., Ltd., Version: <= 1.2.0.0"
        threat_name = "Windows.VulnDriver.JiangmenEyun"
        reference_sample = "ff55c1f308a5694eb66a3e9ba326266c826c5341c44958831a7a59a23ed5ecc8"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4A 69 61 6E 67 6D 65 6E 20 45 79 75 6E 20 4E 65 74 77 6F 72 6B 20 43 6F 2E 2C 20 4C 74 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 44 00 63 00 50 00 72 00 6F 00 74 00 65 00 63 00 74 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "DcProtect.pdb"
        $str2 = "DcProtect (R) Win8.1x86 driver " wide
        $str3 = "DcProtect Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

