rule Windows_VulnDriver_WiseHDInfo_5ab05824 {
    meta:
        author = "Elastic Security"
        id = "5ab05824-1d92-4f84-a30c-225e7aece66e"
        fingerprint = "e8bf2cf98d1f11534e592d50f76c064f3718517fb19a7c0cea58cd4eb6383289"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Name: WiseHDInfo.dll, Version: <= 1.0.2.21"
        threat_name = "Windows.VulnDriver.WiseHDInfo"
        reference_sample = "99244fd0c13d97c133d40c7c0984df7ddcf9b13ad583d4603278e34c66aa4f9d"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 57 00 69 00 73 00 65 00 48 00 44 00 49 00 6E 00 66 00 6F 00 2E 00 64 00 6C 00 6C 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x14][\x00-\x00][\x02-\x02][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x15-\x15][\x00-\x00][\x02-\x02][\x00-\x00])/
        $str1 = "WiseHDInfo.pdb"
        $str2 = "Wise Hardware Information driver" wide
        $str3 = "Hardware Information driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2 and $str3
}

