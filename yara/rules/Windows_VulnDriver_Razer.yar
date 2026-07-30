rule Windows_VulnDriver_Razer_28c1a903 {
    meta:
        author = "Elastic Security"
        id = "28c1a903-1974-44e3-ae59-f219661957d5"
        fingerprint = "92de22bc8a43a0d98d47710a138cf0a003746a9ac518bcc44fcea04e8b97cca6"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Razer USA Ltd., Version: <= 1.0.12.10201"
        threat_name = "Windows.VulnDriver.Razer"
        reference_sample = "46d1dc89cc5fa327e7adf3e3d6d498657240772b85548c17d2e356aac193dd28"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 52 61 7A 65 72 20 55 53 41 20 4C 74 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 52 00 7A 00 70 00 6E 00 6B 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x0b][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x26]|[\x00-\xd8][\x27-\x27])[\x0c-\x0c][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\xd9-\xd9][\x27-\x27][\x0c-\x0c][\x00-\x00])/
        $str1 = "Rzpnk.pdb"
        $str2 = "Razer Overlay Support" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Razer_31d4018e {
    meta:
        author = "Elastic Security"
        id = "31d4018e-0f56-4a25-84b4-f338255ffb43"
        fingerprint = "afb89703fbd625134c541663624a14ad0db6b4a8100753fb82aebb908a01749e"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Razer Inc., Version: <= 1.0.12.7465"
        threat_name = "Windows.VulnDriver.Razer"
        reference_sample = "9724488ca2ba4c787640c49131f4d1daae5bd47d6b2e7e5f9e8918b1d6f655be"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 52 61 7A 65 72 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 52 00 7A 00 70 00 6E 00 6B 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x0b][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x1c]|[\x00-\x28][\x1d-\x1d])[\x0c-\x0c][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x29-\x29][\x1d-\x1d][\x0c-\x0c][\x00-\x00])/
        $str1 = "Rzpnk.pdb"
        $str2 = "Razer Overlay Support" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2
}

