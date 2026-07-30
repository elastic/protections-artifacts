rule Windows_VulnDriver_SsPortAMD64_bb0edd0a {
    meta:
        author = "Elastic Security"
        id = "bb0edd0a-798d-4907-8197-0a048f201be0"
        fingerprint = "f06b8d2664b4fa0539236d551f20b3975f44663b9ab459f4c766aa03ff3ccc1d"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher, Version: <= 8.1.108.0"
        threat_name = "Windows.VulnDriver.SsPortAMD64"
        reference_sample = "83a3159aded44712ae5413743631abe387192edf84f33cdae623c5d94f2ffb01"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 53 00 73 00 50 00 6F 00 72 00 74 00 41 00 4D 00 44 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x07][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x08-\x08][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x08-\x08][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x6b][\x00-\x00]|[\x01-\x01][\x00-\x00][\x08-\x08][\x00-\x00][\x00-\x00][\x00-\x00][\x6c-\x6c][\x00-\x00])/
        $str1 = "SsPort.pdb"
        $str2 = "Serial Solutions for Microsoft Windows 64bits" wide
        $str3 = "SsPort Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_SsPortAMD64_360cf631 {
    meta:
        author = "Elastic Security"
        id = "360cf631-919c-49c0-b32a-a6b77950734a"
        fingerprint = "b31f0cbf054e3c25de79653cdf89f28ddf0b6b37d06ddad20e8212fe9e7f7d75"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Name: SsPortAMD64.sys, Version: <= 7.0.97.0"
        threat_name = "Windows.VulnDriver.SsPortAMD64"
        reference_sample = "b3ea41eabb11e18413e48fe1f7fef37635a464848385f90f7a28498d144bee46"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 53 00 73 00 50 00 6F 00 72 00 74 00 41 00 4D 00 44 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x07-\x07][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x60][\x00-\x00]|[\x00-\x00][\x00-\x00][\x07-\x07][\x00-\x00][\x00-\x00][\x00-\x00][\x61-\x61][\x00-\x00])/
        $str1 = "SsPort.pdb"
        $str2 = "Serial Solutions for Windows XP AMD64" wide
        $str3 = "SsPort Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2 and $str3
}

