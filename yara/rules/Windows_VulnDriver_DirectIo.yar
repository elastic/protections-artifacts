rule Windows_VulnDriver_DirectIo_7bea6c8f {
    meta:
        author = "Elastic Security"
        id = "7bea6c8f-7006-4994-be21-614e3cf1ec76"
        fingerprint = "18a43821655a6d65242a8995b98bc7dc924a65ab7808ee09daf9a82f7794e906"
        creation_date = "2022-04-04"
        last_modified = "2022-04-04"
        threat_name = "Windows.VulnDriver.DirectIo"
        reference_sample = "1dadd707c55413a16320dc70d2ca7784b94c6658331a753b3424ae696c5d93ea"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "\\DirectIo.pdb"
        $str2 = { 9B 49 18 FC CD 5C EA D2 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1 and not $str2
}

rule Windows_VulnDriver_DirectIo_abe8bfa6 {
    meta:
        author = "Elastic Security"
        id = "abe8bfa6-0b51-4224-a7fc-4249e34ac0a2"
        fingerprint = "7fe138f9f951c00ae144029890fd228bf6f6a932c0d7e6cf6555ae10df92c725"
        creation_date = "2022-04-04"
        last_modified = "2022-04-04"
        threat_name = "Windows.VulnDriver.DirectIo"
        reference_sample = "d84e3e250a86227c64a96f6d5ac2b447674ba93d399160850acb2339da43eae5"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "\\DirectIo64.pdb"
        $str2 = { 9B 49 18 FC CD 5C EA D2 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1 and not $str2
}

rule Windows_VulnDriver_DirectIo_e25d1fa8 {
    meta:
        author = "Elastic Security"
        id = "e25d1fa8-0f59-4b52-a66d-1ecdf9a1c18e"
        fingerprint = "0fcf246aad99d144c97ea5705697c8d071b36cc89c3f7039b21d17820027bb7d"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Jernej Simoncic, Version: <= 0.1.0.0"
        threat_name = "Windows.VulnDriver.DirectIo"
        reference_sample = "16461fe1855e4cb4a5e3203f98a69376ad2dc8f69f1d43463206fdd6784b7fbf"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4A 65 72 6E 65 6A 20 53 69 6D 6F 6E 63 69 63 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 64 00 69 00 72 00 65 00 63 00 74 00 69 00 6F 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "directio.pdb"
        $str2 = "DirectIo Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2
}

