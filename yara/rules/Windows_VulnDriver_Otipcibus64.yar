rule Windows_VulnDriver_Otipcibus64_7d564eba {
    meta:
        author = "Elastic Security"
        id = "7d564eba-e43a-41d7-aa8f-f659280bd475"
        fingerprint = "71893f74fe708031558b510d9129ac8eb3ec27a3bc5131b6a1dfb390f079f67a"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Ours Technology Inc., Version: <= 1.1000.0.1"
        threat_name = "Windows.VulnDriver.Otipcibus64"
        reference_sample = "4e3eb5b9bce2fd9f6878ae36288211f0997f6149aa8c290ed91228ba4cdfae80"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4F 75 72 73 20 54 65 63 68 6E 6F 6C 6F 67 79 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6F 00 74 00 69 00 70 00 63 00 69 00 62 00 75 00 73 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x02]|[\x00-\xe7][\x03-\x03])[\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\xe8-\xe8][\x03-\x03][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00]|[\xe8-\xe8][\x03-\x03][\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "phymem.pdb"
        $str2 = "Kernel Mode Driver To Access Physical Memory And Ports" wide
        $str3 = "Hardware Access Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

