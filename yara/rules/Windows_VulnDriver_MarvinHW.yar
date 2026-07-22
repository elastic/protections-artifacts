rule Windows_VulnDriver_MarvinHW_37326842 {
    meta:
        author = "Elastic Security"
        id = "37326842-66a3-4058-abb7-d6d48ca58831"
        fingerprint = "f0ac8176d412dfaeb9c37ce18c13dea7cc2783fd37421b69e19c4dfa898e42be"
        creation_date = "2022-07-21"
        last_modified = "2022-07-21"
        description = "Subject: Marvin Test Solutions, Inc., Name: HW.sys, Version: 4.9.8.0"
        threat_name = "Windows.VulnDriver.MarvinHW"
        reference_sample = "6a4875ae86131a594019dec4abd46ac6ba47e57a88287b814d07d929858fe3e5"
        severity = 100
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 61 72 76 69 6E 20 54 65 73 74 20 53 6F 6C 75 74 69 6F 6E 73 2C 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 48 00 57 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x09][\x00-\x00])([\x00-\x04][\x00-\x00])([\x00-\x00][\x00-\x00])([\x00-\x08][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x03][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x08][\x00-\x00])([\x00-\x04][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x09][\x00-\x00])([\x00-\x04][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\x07][\x00-\x00]))/
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version
}

rule Windows_VulnDriver_MarvinHW_c4cb6fe4 {
    meta:
        author = "Elastic Security"
        id = "c4cb6fe4-a5b6-4cbd-9c5c-c7186fdcfea7"
        fingerprint = "93046c0ad2d79ea6e74a420c8d4d47bf3a25ec289ee87247d7ff6eeb60b79c7a"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Marvin Test Solutions, Inc., Version: <= 4.9.8.0"
        threat_name = "Windows.VulnDriver.MarvinHW"
        reference_sample = "4880f40f2e557cff38100620b9aa1a3a753cb693af16cd3d95841583edcb57a8"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 61 72 76 69 6E 20 54 65 73 74 20 53 6F 6C 75 74 69 6F 6E 73 2C 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 48 00 57 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x08][\x00-\x00][\x04-\x04][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x09-\x09][\x00-\x00][\x04-\x04][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x07][\x00-\x00]|[\x09-\x09][\x00-\x00][\x04-\x04][\x00-\x00][\x00-\x00][\x00-\x00][\x08-\x08][\x00-\x00])/
        $str1 = "HW - Windows NT-10 (32/64 bit) kernel mode driver for PC ports/memory/PCI access" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1
}

rule Windows_VulnDriver_MarvinHW_b0d52834 {
    meta:
        author = "Elastic Security"
        id = "b0d52834-85f3-401c-8393-3d0bb361f7a9"
        fingerprint = "fae2457462a1411c7d432bb08293fc08e451e58c948fbb0be36569111a5e73a6"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Marvin Test Solutions, Inc., Version: <= 4.8.2.0"
        threat_name = "Windows.VulnDriver.MarvinHW"
        reference_sample = "fd388cf1df06d419b14dedbeb24c6f4dff37bea26018775f09d56b3067f0de2c"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 61 72 76 69 6E 20 54 65 73 74 20 53 6F 6C 75 74 69 6F 6E 73 2C 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 48 00 57 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x07][\x00-\x00][\x04-\x04][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x08-\x08][\x00-\x00][\x04-\x04][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00]|[\x08-\x08][\x00-\x00][\x04-\x04][\x00-\x00][\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00])/
        $str1 = "HW - Windows NT-8 (32/64 bit) kernel mode driver for PC ports/memory/PCI access" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1
}

rule Windows_VulnDriver_MarvinHW_64388663 {
    meta:
        author = "Elastic Security"
        id = "64388663-a5ae-4bcd-93f2-cab1242dbfa5"
        fingerprint = "89bcccc416e8320fc77548ae1ed236d10f822ea6b63790f65b75886774d19122"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Name: HW.sys, Version: <= 3.2.0.0"
        threat_name = "Windows.VulnDriver.MarvinHW"
        reference_sample = "b8fcc8ef2b27c0c0622d069981e39f112d3b3b0dbede053340bc157ba1316eab"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 48 00 57 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x01][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "Geotest HW" wide
        $str2 = "HW - Windows NT/2000/XP kernel mode driver for PC ports/memory/PCI access " wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version and $str1 and $str2
}

