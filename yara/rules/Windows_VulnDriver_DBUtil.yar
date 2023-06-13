rule Windows_VulnDriver_DBUtil_ffe07c79 {
    meta:
        author = "Elastic Security"
        id = "ffe07c79-d97b-43ba-92b9-206bb4c7bdd4"
        fingerprint = "16c22aba1e8c677cc22d3925dd7416a3c55c67271940289936a2cdc199a53798"
        creation_date = "2022-04-04"
        last_modified = "2022-04-04"
        threat_name = "Windows.VulnDriver.DBUtil"
        reference_sample = "87e38e7aeaaaa96efe1a74f59fca8371de93544b7af22862eb0e574cec49c7c3"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "\\DBUtilDrv2_32.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

rule Windows_VulnDriver_DBUtil_852ba283 {
    meta:
        author = "Elastic Security"
        id = "852ba283-6a03-44b6-b7e2-b00d1b0586e4"
        fingerprint = "aec919dfea62a8ed01dde4e8c63fbfa9c2a9720c144668460c00f56171c8db25"
        creation_date = "2022-04-04"
        last_modified = "2022-04-04"
        threat_name = "Windows.VulnDriver.DBUtil"
        reference_sample = "0296e2ce999e67c76352613a718e11516fe1b0efc3ffdb8918fc999dd76a73a5"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "\\DBUtilDrv2_64.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

rule Windows_VulnDriver_DBUtil_23afa785 {
    meta:
        author = "Elastic Security"
        id = "23afa785-fd0a-4d6a-b994-fa9e033697b0"
        fingerprint = "af4ad3d99599e0c1e1ac6472194de7055c6ffa11801614a375647eba1a863295"
        creation_date = "2022-04-04"
        last_modified = "2023-06-13"
        threat_name = "Windows.VulnDriver.DBUtil"
        reference_sample = "2e6b339597a89e875f175023ed952aaac64e9d20d457bbc07acf1586e7fe2df8"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "\\DellRingZeroLib\\Common\\Win\\KernelModeDriver\\x64\\Release\\DBUtilDrv2.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

