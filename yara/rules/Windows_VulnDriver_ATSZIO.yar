rule Windows_VulnDriver_ATSZIO_e22cc429 {
    meta:
        author = "Elastic Security"
        id = "e22cc429-0285-4ab1-ae35-7e905e467182"
        fingerprint = "21cf1d00acde85bdae8c4cf6d59b0d224458de30a32dbddebd99eab48e1126bb"
        creation_date = "2022-04-07"
        last_modified = "2022-04-07"
        description = "Name: ATSZIO.sys"
        threat_name = "Windows.VulnDriver.ATSZIO"
        reference_sample = "01e024cb14b34b6d525c642a710bfa14497ea20fd287c39ba404b10a8b143ece"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 41 00 54 00 53 00 5A 00 49 00 4F 00 2E 00 73 00 79 00 73 00 00 00 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name
}

rule Windows_VulnDriver_ATSZIO_47d07464 {
    meta:
        author = "Elastic Security"
        id = "47d07464-9ca7-4317-b89d-9516c4ed4e5c"
        fingerprint = "7f98513cc6e645ea2a1ac53a3babaa2ece0a811562f87ae35ff3fd7fc6d7014e"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher, Version: <= 0.2.1.7"
        threat_name = "Windows.VulnDriver.ATSZIO"
        reference_sample = "1a4f7d7926efc3e3488758ce318246ea78a061bde759ec6c906ff005dd8213e5"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 41 00 54 00 53 00 5A 00 49 00 4F 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00]|[\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x06][\x00-\x00][\x01-\x01][\x00-\x00]|[\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00][\x07-\x07][\x00-\x00][\x01-\x01][\x00-\x00])/
        $str1 = "ATSZIO64.pdb"
        $str2 = "ATSZIO Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

