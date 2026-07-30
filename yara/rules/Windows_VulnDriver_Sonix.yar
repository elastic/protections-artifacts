rule Windows_VulnDriver_Sonix_2a72feee {
    meta:
        author = "Elastic Security"
        id = "2a72feee-3fb3-4afd-a333-0f8fdf7eaa2b"
        fingerprint = "d58bbc4690e4b654deff45058765b6ca39978b9ea67d430980f650a70750c6c4"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: SONIX TECHNOLOGY CO., LTD."
        threat_name = "Windows.VulnDriver.Sonix"
        reference_sample = "85a4ce446d9ccd93c2f14d2e0f30ea673812ce740438abb199a8047510614a76"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 4F 4E 49 58 20 54 45 43 48 4E 4F 4C 4F 47 59 20 43 4F 2E 2C 20 4C 54 44 2E }
        $str1 = "SONiXDDRx64.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

