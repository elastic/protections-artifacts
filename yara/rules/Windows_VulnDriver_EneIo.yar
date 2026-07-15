rule Windows_VulnDriver_EneIo_6e01882f {
    meta:
        author = "Elastic Security"
        id = "6e01882f-8394-4e32-8049-fa9c4588b087"
        fingerprint = "8077212bfbadc7f47f2eb76f123a6e4bcda12009293cb975bbeaba77f8c9dcd0"
        creation_date = "2022-04-04"
        last_modified = "2022-04-04"
        threat_name = "Windows.VulnDriver.EneIo"
        reference_sample = "175eed7a4c6de9c3156c7ae16ae85c554959ec350f1c8aaa6dfe8c7e99de3347"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "\\Release\\EneIo.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

rule Windows_VulnDriver_EneIo_20aedf92 {
    meta:
        author = "Elastic Security"
        id = "20aedf92-e807-4487-bc74-e87affb06880"
        fingerprint = "842645fb40bbdfcc100d01545e8c1b19fc2e8400422641f477a84726d8be605c"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: ENE TECHNOLOGY INC."
        threat_name = "Windows.VulnDriver.EneIo"
        reference_sample = "9ee33ffd80611a13779df6286c1e04d3c151f1e2f65e3d664a08997fcd098ef3"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 45 4E 45 20 54 45 43 48 4E 4F 4C 4F 47 59 20 49 4E 43 2E }
        $str1 = "EneIo.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

