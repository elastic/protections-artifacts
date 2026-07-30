rule Windows_VulnDriver_RealtimeDriver_aabbd3c0 {
    meta:
        author = "Elastic Security"
        id = "aabbd3c0-40c7-4952-af82-21ed7d614388"
        fingerprint = "15c518a7887af3ed0ee2c4da508e070e8c23a22c2cc730d10b9e1ac7b1731193"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: MANDIANT Corporation, Version: <= 10.6.18.0"
        threat_name = "Windows.VulnDriver.RealtimeDriver"
        reference_sample = "1e87c118482101a9acb0952f4545dad155956dd397858b5d2748c63f0d836704"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 41 4E 44 49 41 4E 54 20 43 6F 72 70 6F 72 61 74 69 6F 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 52 00 65 00 61 00 6C 00 74 00 69 00 6D 00 65 00 20 00 44 00 72 00 69 00 76 00 65 00 72 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x09][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x05][\x00-\x00][\x0a-\x0a][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x06-\x06][\x00-\x00][\x0a-\x0a][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x11][\x00-\x00]|[\x06-\x06][\x00-\x00][\x0a-\x0a][\x00-\x00][\x00-\x00][\x00-\x00][\x12-\x12][\x00-\x00])/
        $str1 = "mrt_wfp.pdb"
        $str2 = "IOCTL_COLLECTION_GETDATA"
        $str3 = "IOCTL_COLLECTION_START"
        $str4 = "Realtime Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4
}

