rule Windows_VulnDriver_RivetNetworks_c6225136 {
    meta:
        author = "Elastic Security"
        id = "c6225136-a2fb-4a78-9a59-c8d483c197e3"
        fingerprint = "d938e472ef2b46303211a7ccf287d1776ceb297cbc333bd70f946bb16c8904a1"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Rivet Networks LLC, Version: <= 9.7.4.11"
        threat_name = "Windows.VulnDriver.RivetNetworks"
        reference_sample = "b583414fcee280128788f7b39451c511376fe821f455d4f3702795e96d560704"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 52 69 76 65 74 20 4E 65 74 77 6F 72 6B 73 20 4C 4C 43 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4B 00 66 00 65 00 43 00 6F 00 44 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x08][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x06][\x00-\x00][\x09-\x09][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x07-\x07][\x00-\x00][\x09-\x09][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x03][\x00-\x00]|[\x07-\x07][\x00-\x00][\x09-\x09][\x00-\x00][\x00-\x0a][\x00-\x00][\x04-\x04][\x00-\x00]|[\x07-\x07][\x00-\x00][\x09-\x09][\x00-\x00][\x0b-\x0b][\x00-\x00][\x04-\x04][\x00-\x00])/
        $str1 = "KfeCo10x64.pdb"
        $str2 = "Killer Traffic Control" wide
        $str3 = "Killer Traffic Control Callout Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

