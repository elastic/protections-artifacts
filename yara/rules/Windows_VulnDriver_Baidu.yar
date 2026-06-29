rule Windows_VulnDriver_Baidu_33e4d411 {
    meta:
        author = "Elastic Security"
        id = "33e4d411-cec1-4cdc-b413-12a9f3b8188d"
        fingerprint = "e8b4b53520291f41f0c12461a85093c6bfb961ba621f0e106c0f73c6eff7d52e"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: 山西荣升源科贸有限公司, Version: <= 5.0.3.18797"
        threat_name = "Windows.VulnDriver.Baidu"
        reference_sample = "375559359bf5a1d4e132d9e09fc67b3bb55cd07639d49c039267ff22de28b427"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] E5 B1 B1 E8 A5 BF E8 8D A3 E5 8D 87 E6 BA 90 E7 A7 91 E8 B4 B8 E6 9C 89 E9 99 90 E5 85 AC E5 8F B8 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x04][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00]|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x48]|[\x00-\x6c][\x49-\x49])[\x03-\x03][\x00-\x00]|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00][\x6d-\x6d][\x49-\x49][\x03-\x03][\x00-\x00])/
        $str1 = "BdApiUtil64.pdb"
        $str2 = "Baidu Antivirus" wide
        $str3 = "Baidu Antivirus BdApi Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Baidu_03175bb0 {
    meta:
        author = "Elastic Security"
        id = "03175bb0-3e14-4fa0-95b5-207418029cd1"
        fingerprint = "19a149595fa952e01c7fa5ebe662d8c8b49fbd09b156a9df5145a8eff89a0f88"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: Baidu Online Network Technology (Beijing)Co., Ltd, Version: <= 5.4.3.53276"
        threat_name = "Windows.VulnDriver.Baidu"
        reference_sample = "568ad3abf24d40c811ba56d880123641d3796ba79eed4777b28c03fd97a9ee16"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 42 61 69 64 75 20 4F 6E 6C 69 6E 65 20 4E 65 74 77 6F 72 6B 20 54 65 63 68 6E 6F 6C 6F 67 79 20 28 42 65 69 6A 69 6E 67 29 43 6F 2E 2C 20 4C 74 64 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x04][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x03][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x04-\x04][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00]|[\x04-\x04][\x00-\x00][\x05-\x05][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\xcf]|[\x00-\x1b][\xd0-\xd0])[\x03-\x03][\x00-\x00]|[\x04-\x04][\x00-\x00][\x05-\x05][\x00-\x00][\x1c-\x1c][\xd0-\xd0][\x03-\x03][\x00-\x00])/
        $str1 = "BdApiUtil64.pdb"
        $str2 = "Baidu Antivirus" wide
        $str3 = "Baidu Antivirus BdApi Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Baidu_63b3f755 {
    meta:
        author = "Elastic Security"
        id = "63b3f755-12bb-4e7f-9046-852cae8f05aa"
        fingerprint = "a970801c70d2a72cf0ae28889c57b164c317c6fb1e0c5af5362e6c1643a7cfae"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: BAF GERMANY PRIVATE LIMITED, Version: <= 5.0.3.18797"
        threat_name = "Windows.VulnDriver.Baidu"
        reference_sample = "80ca1beedf8b7a9b49a78cec959f3d75de208d179de64df7d7f66a620819d5b9"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 42 41 46 20 47 45 52 4D 41 4E 59 20 50 52 49 56 41 54 45 20 4C 49 4D 49 54 45 44 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x04][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00]|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x48]|[\x00-\x6c][\x49-\x49])[\x03-\x03][\x00-\x00]|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00][\x6d-\x6d][\x49-\x49][\x03-\x03][\x00-\x00])/
        $str1 = "BdApiUtil64.pdb"
        $str2 = "Baidu Antivirus" wide
        $str3 = "Baidu Antivirus BdApi Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Baidu_a47d1415 {
    meta:
        author = "Elastic Security"
        id = "a47d1415-cf14-4062-880d-e1f09270dc6e"
        fingerprint = "42538b42d4293ea0f1b04a2ad116bf601cbd139a2dd4ec53d80373a1ae245ff0"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: Partner Tech(Shanghai)Co.,Ltd, Version: <= 5.0.3.18797"
        threat_name = "Windows.VulnDriver.Baidu"
        reference_sample = "bc84e03955d94bcda5bbe00871417c9f0e3200df43040cdf674684084ea0db09"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 50 61 72 74 6E 65 72 20 54 65 63 68 28 53 68 61 6E 67 68 61 69 29 43 6F 2E 2C 4C 74 64 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x04][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00]|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x48]|[\x00-\x6c][\x49-\x49])[\x03-\x03][\x00-\x00]|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00][\x6d-\x6d][\x49-\x49][\x03-\x03][\x00-\x00])/
        $str1 = "BdApiUtil64.pdb"
        $str2 = "Baidu Antivirus" wide
        $str3 = "Baidu Antivirus BdApi Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Baidu_225408a6 {
    meta:
        author = "Elastic Security"
        id = "225408a6-3ac0-4db2-9261-e6ecfd46b47f"
        fingerprint = "6ce66da6551161cc0addc21fd3031be53fae7b26521f73d7317b4cea537345a9"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: Baidu Online Network Technology (Beijing) Co.,Ltd., Version: <= 5.4.3.59571"
        threat_name = "Windows.VulnDriver.Baidu"
        reference_sample = "d2edf53be389c59eff114694576a0c55cdf1b3ef266121ecdae11e711d433032"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 42 61 69 64 75 20 4F 6E 6C 69 6E 65 20 4E 65 74 77 6F 72 6B 20 54 65 63 68 6E 6F 6C 6F 67 79 20 28 42 65 69 6A 69 6E 67 29 20 43 6F 2E 2C 4C 74 64 2E }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x04][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x03][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x04-\x04][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00]|[\x04-\x04][\x00-\x00][\x05-\x05][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\xe7]|[\x00-\xb2][\xe8-\xe8])[\x03-\x03][\x00-\x00]|[\x04-\x04][\x00-\x00][\x05-\x05][\x00-\x00][\xb3-\xb3][\xe8-\xe8][\x03-\x03][\x00-\x00])/
        $str1 = "BdApiUtil64.pdb"
        $str2 = "Baidu Antivirus" wide
        $str3 = "Baidu Antivirus BdApi Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1 and $str2 and $str3
}

