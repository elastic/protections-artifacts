rule Windows_VulnDriver_IREC_0224fbc5 {
    meta:
        author = "Elastic Security"
        id = "0224fbc5-c6e2-4da5-aeb0-da62bd7695f2"
        fingerprint = "c776b53e33cd4e28a48811f32e09636579a83611c2b52af1d6c3480490d00db8"
        creation_date = "2026-07-23"
        last_modified = "2026-08-11"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher"
        threat_name = "Windows.VulnDriver.IREC"
        reference_sample = "dd573f23d656818036fc9ae1064eda31aca86acb9bc44a6e127db3ea112a9094"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $str1 = "X:\\Projects\\Binalyze\\Binalyze.IREC\\Binalyze.IREC.Driver\\bin\\x64\\irec64.pdb"
        $str2 = "IOCTL_CREATE_OBJECT_DIRECTORY_SNAPSHOT_RESPONSE"
        $str3 = "IOCTL_CREATE_OBJECT_DIRECTORY_SNAPSHOT_REQUEST"
        $seq1 = { 48 8B 44 24 58 48 8B 40 20 8B 40 04 83 E0 01 83 F8 01 74 31 48 8B 44 24 58 48 8B 40 20 8B 40 04 25 00 08 00 00 3D 00 08 00 00 74 19 48 8B 44 24 58 48 8B 40 20 8B 40 04 83 E0 02 83 F8 02 74 05 E9 14 01 00 00 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2 and $str3 and $seq1
}

