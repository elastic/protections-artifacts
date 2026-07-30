rule Windows_VulnDriver_Systweak_9388e2b8 {
    meta:
        author = "Elastic Security"
        id = "9388e2b8-668e-4c4d-9e20-239828169340"
        fingerprint = "07a4b5de857f7a58649dcdf24d70f4cda198436807718eed1a4dcb4108960fec"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: SYSTWEAK SOFTWARE PVT. LTD., Version: <= 1.5.9.7"
        threat_name = "Windows.VulnDriver.Systweak"
        reference_sample = "47e35f474f259314c588af35e88561a015801b52db523eb75fc7eccff8b3be4d"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 59 53 54 57 45 41 4B 20 53 4F 46 54 57 41 52 45 20 50 56 54 2E 20 4C 54 44 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6E 00 65 00 74 00 66 00 69 00 6C 00 74 00 65 00 72 00 32 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x04][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x05-\x05][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x08][\x00-\x00]|[\x05-\x05][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x06][\x00-\x00][\x09-\x09][\x00-\x00]|[\x05-\x05][\x00-\x00][\x01-\x01][\x00-\x00][\x07-\x07][\x00-\x00][\x09-\x09][\x00-\x00])/
        $str1 = "netfilter2.pdb"
        $str2 = "Windows (R) Win 7 DDK driver" wide
        $str3 = "NetFilter SDK WFP Driver (WPP)" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

