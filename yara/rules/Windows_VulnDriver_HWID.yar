rule Windows_VulnDriver_HWID_45bff2d2 {
    meta:
        author = "Elastic Security"
        id = "45bff2d2-ccea-4afd-a459-844225badac7"
        fingerprint = "64a7fb6ae92aa9899cdc492dfc0458637c3ed813102fbec657ba7eca1b96405c"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: WDKTestCert LuckyStrike,132606458839688289"
        threat_name = "Windows.VulnDriver.HWID"
        reference_sample = "321cc3f24a518c70fb537ee9472b1777d05727c649d5b6538082a971c40ddcbe"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 57 44 4B 54 65 73 74 43 65 72 74 20 4C 75 63 6B 79 53 74 72 69 6B 65 2C 31 33 32 36 30 36 34 35 38 38 33 39 36 38 38 32 38 39 }
        $str1 = "hwid-shifter.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

