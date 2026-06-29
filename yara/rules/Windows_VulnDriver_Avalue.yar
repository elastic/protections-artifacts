rule Windows_VulnDriver_Avalue_f3299506 {
    meta:
        author = "Elastic Security"
        id = "f3299506-7bc1-43c1-8356-47a4b2989922"
        fingerprint = "7f703047ba84821b96632bc7b2480ac8a485eff108f2fdf543a79e3ad19cfec4"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: Avalue Technology Inc., Version: <= 2.0.2.0"
        threat_name = "Windows.VulnDriver.Avalue"
        reference_sample = "defde359045213ae6ae278e2a92c5b4a46a74119902364c7957a38138e9c9bbd"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 76 61 6C 75 65 20 54 65 63 68 6E 6F 6C 6F 67 79 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 41 00 56 00 41 00 4C 00 55 00 45 00 49 00 4F 00 2E 00 53 00 59 00 53 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00])/
        $str1 = "avalueio.pdb"
        $str2 = "AvalueIO " wide
        $str3 = "AvalueIO Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

