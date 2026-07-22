rule Windows_VulnDriver_Marte_a0b03aa8 {
    meta:
        author = "Elastic Security"
        id = "a0b03aa8-18d8-4d6e-9ba5-03bdbc15f25e"
        fingerprint = "272154374bde062bc059a5da7433cfa77f1da37ad0534675b02e680e26610a2e"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: EVANGEL TECHNOLOGY (HK) LIMITED"
        threat_name = "Windows.VulnDriver.Marte"
        reference_sample = "167730744bd7cb117aae9931f81d20cbd2ec6eee480388c53d2fc973ede920ea"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 45 56 41 4E 47 45 4C 20 54 45 43 48 4E 4F 4C 4F 47 59 20 28 48 4B 29 20 4C 49 4D 49 54 45 44 }
        $str1 = "nvflash.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

