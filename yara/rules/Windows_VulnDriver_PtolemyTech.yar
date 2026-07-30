rule Windows_VulnDriver_PtolemyTech_5b1a9d0c {
    meta:
        author = "Elastic Security"
        id = "5b1a9d0c-c775-4429-9f55-a4319fadeae5"
        fingerprint = "134fe335211c122e09011d0c9782f920df6617ec6aa4e652243be053aa34c18a"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Ptolemy Tech Co., Ltd"
        threat_name = "Windows.VulnDriver.PtolemyTech"
        reference_sample = "810513b3f4c8d29afb46f71816350088caacf46f1be361af55b26f3fee4662c3"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 50 74 6F 6C 65 6D 79 20 54 65 63 68 20 43 6F 2E 2C 20 4C 74 64 }
        $str1 = "EneIo.pdb"
        $str2 = "IOCTL_WINIO_UNMAPPHYSADDR"
        $str3 = "IOCTL_WINIO_MAPPHYSTOLIN"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2 and $str3
}

