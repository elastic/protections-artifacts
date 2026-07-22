rule Windows_VulnDriver_OMRON_137bb027 {
    meta:
        author = "Elastic Security"
        id = "137bb027-8920-4c27-b578-45211a909665"
        fingerprint = "dd5f1bbfebd9f62677fe13c8f9aee28a8546ea35e4bbca6ae69c0d1307e71b44"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: OMRON Corporation"
        threat_name = "Windows.VulnDriver.OMRON"
        reference_sample = "ae71f40f06edda422efcd16f3a48f5b795b34dd6d9bb19c9c8f2e083f0850eb7"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4F 4D 52 4F 4E 20 43 6F 72 70 6F 72 61 74 69 6F 6E }
        $str1 = "FH-EtherCAT_DIO.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

