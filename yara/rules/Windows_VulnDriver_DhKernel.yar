rule Windows_VulnDriver_DhKernel_966ac37e {
    meta:
        author = "Elastic Security"
        id = "966ac37e-e131-4316-af72-c0764f42fdc0"
        fingerprint = "5d37e16b174e23ffdb53d935ef6d7307bb8b3afe08aa531d21aebdaca6d42d27"
        creation_date = "2026-07-25"
        last_modified = "2026-08-11"
        description = "Subject: YY Inc., Version: <= 1.0.99.0"
        threat_name = "Windows.VulnDriver.DhKernel"
        reference_sample = "bb50818a07b0eb1bd317467139b7eb4bad6cd89053fecdabfeae111689825955"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 59 59 20 49 6E 63 2E }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x62][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x63-\x63][\x00-\x00])/
        $str1 = "Dh_Kernel.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0002 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1
}

rule Windows_VulnDriver_DhKernel_81120ea0 {
    meta:
        author = "Elastic Security"
        id = "81120ea0-3867-411f-b8ff-8247810150db"
        fingerprint = "c21b1ae3b6deb286d78da3a84e2e04ca7c796a3c2fcc876c8ccc0ecb5592bf03"
        creation_date = "2026-07-25"
        last_modified = "2026-08-11"
        description = "Subject: YY Inc., Version: <= 1.0.99.0"
        threat_name = "Windows.VulnDriver.DhKernel"
        reference_sample = "80cbba9f404df3e642f22c476664d63d7c229d45d34f5cd0e19c65eb41becec3"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 59 59 20 49 6E 63 2E }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x62][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x63-\x63][\x00-\x00])/
        $str1 = "Dh_Kernel_10.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0002 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1
}

