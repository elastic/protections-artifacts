rule Windows_VulnDriver_Teramind_5a8c34ce {
    meta:
        author = "Elastic Security"
        id = "5a8c34ce-037a-4d10-be73-887f26b63de1"
        fingerprint = "131c4eba08ecf3a483182df6a39affcb81f8d96db35c68afc3f51ccb21195c94"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Teramind Inc."
        threat_name = "Windows.VulnDriver.Teramind"
        reference_sample = "2cea1a8d5d23a5ed2c2ac2a0c7c0d95da516aa355224cc707f86de8ade5880ef"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 54 65 72 61 6D 69 6E 64 20 49 6E 63 2E }
        $str1 = "tmfsdrv2.pdb"
        $str2 = "IOCTL_STORAGE_QUERY_PROPERTY"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2
}

rule Windows_VulnDriver_Teramind_ee790bc4 {
    meta:
        author = "Elastic Security"
        id = "ee790bc4-8401-4d89-b797-ff275b334571"
        fingerprint = "725b9f6f0c96a60321d0c8867c8363fc152b79188fb8ad6bc5bad13914224391"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Teramind Inc., Version: <= 25.38.2933.0"
        threat_name = "Windows.VulnDriver.Teramind"
        reference_sample = "e9fda504c9bdbe785c55a279ebb27e31783155570ab0c242e1de5bf79fbca6ed"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 54 65 72 61 6D 69 6E 64 20 49 6E 63 2E }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x18][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x25][\x00-\x00][\x19-\x19][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x26-\x26][\x00-\x00][\x19-\x19][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x0a]|[\x00-\x74][\x0b-\x0b])|[\x26-\x26][\x00-\x00][\x19-\x19][\x00-\x00][\x00-\x00][\x00-\x00][\x75-\x75][\x0b-\x0b])/
        $str1 = "netfilter2.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1
}

