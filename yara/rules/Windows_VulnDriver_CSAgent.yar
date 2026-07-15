rule Windows_VulnDriver_CSAgent_a9947237 {
    meta:
        author = "Elastic Security"
        id = "a9947237-806d-4202-a3db-f845fb38d4a4"
        fingerprint = "b72c0c4cb9c8c82bd03fc7c4a58eeda53b9f24603d1cae2f49b28bdb5e8d2630"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: 长沙恒祥信息技术有限公司, Version: <= 6.34.14806.0"
        threat_name = "Windows.VulnDriver.CSAgent"
        reference_sample = "06eccd102c9105957773b32538943531d9c39d0a504ceb3b9b155e97e3b0b134"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] E9 95 BF E6 B2 99 E6 81 92 E7 A5 A5 E4 BF A1 E6 81 AF E6 8A 80 E6 9C AF E6 9C 89 E9 99 90 E5 85 AC E5 8F B8 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 43 00 53 00 41 00 67 00 65 00 6E 00 74 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x21][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x22-\x22][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x38]|[\x00-\xd5][\x39-\x39])|[\x22-\x22][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\x00][\x00-\x00][\xd6-\xd6][\x39-\x39])/
        $str1 = "CrowdStrike Falcon Sensor" wide
        $str2 = "CrowdStrike Falcon Sensor Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_CSAgent_0e7710bf {
    meta:
        author = "Elastic Security"
        id = "0e7710bf-9fb6-49d5-b60f-59a826ffe9e1"
        fingerprint = "592a9106b2ba8e72fa9be66596b01f2c7fa0ec76292a78c72c8c5aa5a072aa1f"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Fuzhou Dingxin Trade Co., Ltd., Version: <= 6.34.14806.0"
        threat_name = "Windows.VulnDriver.CSAgent"
        reference_sample = "1e42c8cb410a7ed653cfe62bbd8cf191f31a47337fe1ffcc35232d03f2da05ef"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 46 75 7A 68 6F 75 20 44 69 6E 67 78 69 6E 20 54 72 61 64 65 20 43 6F 2E 2C 20 4C 74 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 43 00 53 00 41 00 67 00 65 00 6E 00 74 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x21][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x22-\x22][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x38]|[\x00-\xd5][\x39-\x39])|[\x22-\x22][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\x00][\x00-\x00][\xd6-\xd6][\x39-\x39])/
        $str1 = "CrowdStrike Falcon Sensor" wide
        $str2 = "CrowdStrike Falcon Sensor Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_CSAgent_08e01875 {
    meta:
        author = "Elastic Security"
        id = "08e01875-19a1-4cdf-a648-63c9c9f6d0bf"
        fingerprint = "5ad28c36c549da1ca4d0dc248656d3c8f7d69dfd603002653e3de40370867362"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: FEI XIAO, Version: <= 6.34.14806.0"
        threat_name = "Windows.VulnDriver.CSAgent"
        reference_sample = "94b87b1cdaf1d86c2bc4eacef45608d0f16fdd3b981b88cdddc16b6bc64fe25d"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 46 45 49 20 58 49 41 4F }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 43 00 53 00 41 00 67 00 65 00 6E 00 74 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x21][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x22-\x22][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x38]|[\x00-\xd5][\x39-\x39])|[\x22-\x22][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\x00][\x00-\x00][\xd6-\xd6][\x39-\x39])/
        $str1 = "CrowdStrike Falcon Sensor" wide
        $str2 = "CrowdStrike Falcon Sensor Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_CSAgent_3f6d93e7 {
    meta:
        author = "Elastic Security"
        id = "3f6d93e7-e6a5-45c7-afdc-60dccfe77a41"
        fingerprint = "1c54d83ea90d20f2641fb93e66103028f1e93c390e657384457a3e5c59a499d3"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: 新疆亿事联网络科技有限公司, Version: <= 6.34.14806.0"
        threat_name = "Windows.VulnDriver.CSAgent"
        reference_sample = "b2ff9ef50ae037bb003d7157ea8da008a48f715a78c644b5f027b070bf5eb049"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] E6 96 B0 E7 96 86 E4 BA BF E4 BA 8B E8 81 94 E7 BD 91 E7 BB 9C E7 A7 91 E6 8A 80 E6 9C 89 E9 99 90 E5 85 AC E5 8F B8 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 43 00 53 00 41 00 67 00 65 00 6E 00 74 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x21][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x22-\x22][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x38]|[\x00-\xd5][\x39-\x39])|[\x22-\x22][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\x00][\x00-\x00][\xd6-\xd6][\x39-\x39])/
        $str1 = "CrowdStrike Falcon Sensor" wide
        $str2 = "CrowdStrike Falcon Sensor Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_CSAgent_6a60b5bb {
    meta:
        author = "Elastic Security"
        id = "6a60b5bb-26a5-417f-bde7-bb3fc81c81b5"
        fingerprint = "41d0d9a664bb888b487fbc3f8abc84ecf5039e4a6c80ca99bf4286a0dba93147"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Shenzhen yundian Technology Co., Ltd, Version: <= 6.34.14806.0"
        threat_name = "Windows.VulnDriver.CSAgent"
        reference_sample = "b7703a59c39a0d2f7ef6422945aaeaaf061431af0533557246397551b8eed505"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 68 65 6E 7A 68 65 6E 20 79 75 6E 64 69 61 6E 20 54 65 63 68 6E 6F 6C 6F 67 79 20 43 6F 2E 2C 20 4C 74 64 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 43 00 53 00 41 00 67 00 65 00 6E 00 74 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x21][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x22-\x22][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x38]|[\x00-\xd5][\x39-\x39])|[\x22-\x22][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\x00][\x00-\x00][\xd6-\xd6][\x39-\x39])/
        $str1 = "pVVIOoBMRFmpaxPTpRhQmuJdkV.pdb"
        $str2 = "CrowdStrike Falcon Sensor" wide
        $str3 = "CrowdStrike Falcon Sensor Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

