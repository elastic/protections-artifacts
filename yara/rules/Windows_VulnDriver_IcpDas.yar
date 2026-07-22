rule Windows_VulnDriver_IcpDas_24c997de {
    meta:
        author = "Elastic Security"
        id = "24c997de-9192-4603-a6fd-4d64fee365e4"
        fingerprint = "3cc18db1cb08561c7bc7bdb83879443dcd364f215c91cfd6a1e20e65fa6e0013"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: ICP DAS Co., LTD."
        threat_name = "Windows.VulnDriver.IcpDas"
        reference_sample = "8a6265d23d30d6c4c7e159624686de6dbf2ccb86a421b0f45510005f7a40cd1a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 43 50 20 44 41 53 20 43 6F 2E 2C 20 4C 54 44 2E }
        $str1 = "CardIo.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

