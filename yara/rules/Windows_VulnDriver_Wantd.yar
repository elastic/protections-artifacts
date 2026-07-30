rule Windows_VulnDriver_Wantd_7cdc2fe4 {
    meta:
        author = "Elastic Security"
        id = "7cdc2fe4-6c7a-401f-96df-70541e1140fc"
        fingerprint = "eb27eddd35bb0827dc12937f10ddae5416a6ba85475102c3c1a198b350fdfe4e"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Anhua Xinda (Beijing) Technology Co., Ltd., Version: <= 6.0.0.0"
        threat_name = "Windows.VulnDriver.Wantd"
        reference_sample = "06a0ec9a316eb89cb041b1907918e3ad3b03842ec65f004f6fa74d57955573a4"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 6E 68 75 61 20 58 69 6E 64 61 20 28 42 65 69 6A 69 6E 67 29 20 54 65 63 68 6E 6F 6C 6F 67 79 20 43 6F 2E 2C 20 4C 74 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 77 00 61 00 6E 00 74 00 64 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "Microsoft Windows Operating System" wide
        $str2 = "WAN Transport Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Wantd_460d7585 {
    meta:
        author = "Elastic Security"
        id = "460d7585-1f93-4f7a-ab52-510e5187fbf9"
        fingerprint = "90d4bb324da86ef8fe634722d79a82b15d12297c130f1b467ed52fe62ebcf933"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Name: wantd.sys, Version: <= 5.0.0.0"
        threat_name = "Windows.VulnDriver.Wantd"
        reference_sample = "81c7bb39100d358f8286da5e9aa838606c98dfcc263e9a82ed91cd438cb130d1"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 77 00 61 00 6E 00 74 00 64 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x04][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "Microsoft Windows Operating System" wide
        $str2 = "WAN Transport Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version and $str1 and $str2
}

