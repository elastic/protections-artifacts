rule Windows_VulnDriver_Micsys_b1db31b5 {
    meta:
        author = "Elastic Security"
        id = "b1db31b5-f79e-4453-bc5b-04e5746adfce"
        fingerprint = "98cfb23e27884f1428ff85b13a283dd9e4294512a0cc3fdbd77a71d6e93c8e1a"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: MICSYS Technology Co., Ltd."
        threat_name = "Windows.VulnDriver.Micsys"
        reference_sample = "525d9b51a80ca0cd4c5889a96f857e73f3a80da1ffbae59851e0f51bdfb0b6cd"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 49 43 53 59 53 20 54 65 63 68 6E 6F 6C 6F 67 79 20 43 6F 2E 2C 20 4C 74 64 2E }
        $str1 = "MsIo64.pdb"
        $str2 = "IOCTL_MSIO_UNMAPPHYSADDR"
        $str3 = "IOCTL_MSIO_MAPPHYSTOLIN"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2 and $str3
}

