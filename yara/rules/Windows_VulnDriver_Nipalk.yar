rule Windows_VulnDriver_Nipalk_17c9d0c2 {
    meta:
        author = "Elastic Security"
        id = "17c9d0c2-62b4-412b-8589-108cf1618ae2"
        fingerprint = "46aafd450acd7ad19f03ce8e5f851c507f196b319ae24f4c57a3a871846b8faf"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: National Instruments Corporation, Version: <= 25.2048.3.138"
        threat_name = "Windows.VulnDriver.Nipalk"
        reference_sample = "1a6b4d5ad40c9ddf2599f6a44e94a1336aa3d28bf6a220b775f5c3305faecb2d"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4E 61 74 69 6F 6E 61 6C 20 49 6E 73 74 72 75 6D 65 6E 74 73 20 43 6F 72 70 6F 72 61 74 69 6F 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6E 00 69 00 70 00 61 00 6C 00 6B 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x18][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x06]|[\x00-\xff][\x07-\x07])[\x19-\x19][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x08-\x08][\x19-\x19][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00]|[\x00-\x00][\x08-\x08][\x19-\x19][\x00-\x00][\x00-\x89][\x00-\x00][\x03-\x03][\x00-\x00]|[\x00-\x00][\x08-\x08][\x19-\x19][\x00-\x00][\x8a-\x8a][\x00-\x00][\x03-\x03][\x00-\x00])/
        $str1 = "nipalk.pdb"
        $str2 = "iDMAChannel_removeSampleTransferredObserver"
        $str3 = "tPIMMblockReference_unassignExternalPointer"
        $str4 = "NI-PAL Driver for Windows" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4
}

