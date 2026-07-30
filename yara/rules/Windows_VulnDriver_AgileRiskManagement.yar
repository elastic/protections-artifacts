rule Windows_VulnDriver_AgileRiskManagement_66938a5b {
    meta:
        author = "Elastic Security"
        id = "66938a5b-66a0-4c69-b6a8-7e717abad5c0"
        fingerprint = "95d4ed904bdafe8b3d5dc39d1c9cb8319e0b6f3ec360f58dd0d6e36ea0f106f6"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Agile Risk Management LLC"
        threat_name = "Windows.VulnDriver.AgileRiskManagement"
        reference_sample = "2ccd04383dc2f1f777b7712c6f8ee6d05afac98d22cad8e96f5172ba9c5c53b0"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 67 69 6C 65 20 52 69 73 6B 20 4D 61 6E 61 67 65 6D 65 6E 74 20 4C 4C 43 }
        $str1 = "Mnemosyne_x64.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

