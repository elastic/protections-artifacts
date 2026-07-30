rule Windows_VulnDriver_Titidrv_da6d6d3f {
    meta:
        author = "Elastic Security"
        id = "da6d6d3f-e128-4a70-8f8c-61da732e2db0"
        fingerprint = "9ba4bedb8f7b86841dc80914898f865740dda1d140a06cc0a67beae7405a2614"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Benjamin Delpy, Version: <= 2.1.0.0"
        threat_name = "Windows.VulnDriver.Titidrv"
        reference_sample = "208ea38734979aa2c86332eba1ea5269999227077ff110ac0a0d411073165f85"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 42 65 6E 6A 61 6D 69 6E 20 44 65 6C 70 79 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 74 00 69 00 74 00 69 00 64 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "mimidrv.pdb"
        $str2 = "titidrv (titicatz)" wide
        $str3 = "titidrv for Windows (titicatz)" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

