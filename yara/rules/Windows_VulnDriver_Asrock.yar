rule Windows_VulnDriver_Asrock_986d2d3c {
    meta:
        author = "Elastic Security"
        id = "986d2d3c-96d1-4c74-a594-51c6df3b2896"
        fingerprint = "17a021c4130a41ca6714f2dd7f33c100ba61d6d2d4098a858f917ab49894b05b"
        creation_date = "2022-04-04"
        last_modified = "2022-04-04"
        threat_name = "Windows.VulnDriver.Asrock"
        reference_sample = "3943a796cc7c5352aa57ccf544295bfd6fb69aae147bc8235a00202dc6ed6838"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "\\AsrDrv106.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

rule Windows_VulnDriver_Asrock_cdf192f9 {
    meta:
        author = "Elastic Security"
        id = "cdf192f9-c62f-4e00-b6a9-df85d10fee99"
        fingerprint = "f27c61c67b51ab88994742849dcd1311064ef0cacddb57503336d08f45059060"
        creation_date = "2022-04-04"
        last_modified = "2022-04-04"
        threat_name = "Windows.VulnDriver.Asrock"
        reference_sample = "2003b478b9fd1b3d76ec5bf4172c2e8915babbbee7ad1783794acbf8d4c2519d"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "\\AsrDrv103.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

rule Windows_VulnDriver_Asrock_aee156a5 {
    meta:
        author = "Elastic Security"
        id = "aee156a5-a841-4a9d-97de-1d935705b4bb"
        fingerprint = "ced97dd50a1525aeafef2192c16c1a4f29d6c70e7b3c4b196352cfc2a5c8f157"
        creation_date = "2022-04-07"
        last_modified = "2022-04-07"
        description = "Name: RwDrv.sys"
        threat_name = "Windows.VulnDriver.Asrock"
        reference_sample = "3c5bf92c26398695f9ced7ce647a7e9f6ddcc89eea66b45aa3607196a187431b"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 52 00 77 00 44 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name
}

