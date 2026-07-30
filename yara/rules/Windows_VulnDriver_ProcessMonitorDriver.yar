rule Windows_VulnDriver_ProcessMonitorDriver_89e06ec6 {
    meta:
        author = "Elastic Security"
        id = "89e06ec6-9bff-4491-b413-913ae0eb7534"
        fingerprint = "d3f873517ed0cfaa0aaa09d3512f06b344d1aa9fb97a13aa486eb9eb4bd0cd5e"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher, Version: <= 11.26.18.0"
        threat_name = "Windows.VulnDriver.ProcessMonitorDriver"
        reference_sample = "5b4f59236a9b950bcd5191b35d19125f60cfb9e1a1e1aa2e4f914b6745dde9df"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 50 00 72 00 6F 00 63 00 65 00 73 00 73 00 4D 00 6F 00 6E 00 69 00 74 00 6F 00 72 00 44 00 72 00 69 00 76 00 65 00 72 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x0a][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x19][\x00-\x00][\x0b-\x0b][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x1a-\x1a][\x00-\x00][\x0b-\x0b][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x11][\x00-\x00]|[\x1a-\x1a][\x00-\x00][\x0b-\x0b][\x00-\x00][\x00-\x00][\x00-\x00][\x12-\x12][\x00-\x00])/
        $str1 = "ProcessMonitorDriver.pdb"
        $str2 = "_debugBootBuffer"
        $str3 = "Safetica" wide
        $str4 = "ProcessMonitor Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4
}

