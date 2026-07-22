rule Windows_VulnDriver_Ntbios_43a7abb2 {
    meta:
        author = "Elastic Security"
        id = "43a7abb2-3f29-4428-adb5-44ddcfdc4ad7"
        fingerprint = "a2873f8d67c9e6d184288ea7ee187e237a74721ec5c847e84322bf6ae5805856"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Name: ntbios.sys, Version: <= 5.0.2.1"
        threat_name = "Windows.VulnDriver.Ntbios"
        reference_sample = "96bf3ee7c6673b69c6aa173bb44e21fa636b1c2c73f4356a7599c121284a51cc"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6E 00 74 00 62 00 69 00 6F 00 73 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x04][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00]|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00]|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00][\x01-\x01][\x00-\x00][\x02-\x02][\x00-\x00])/
        $str1 = " Microsoft(R) Windows (R) NT Operating System" wide
        $str2 = "ntbios driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version and $str1 and $str2
}

