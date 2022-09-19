rule Windows_VulnDriver_Zam_928812a7 {
    meta:
        author = "Elastic Security"
        id = "928812a7-ac7c-47cf-9111-11470b661d46"
        fingerprint = "8e5db0d4fee806538929680e7d3521b111b0e09fcc3eba3c191f6787375999cc"
        creation_date = "2022-04-04"
        last_modified = "2022-04-04"
        threat_name = "Windows.VulnDriver.Zam"
        reference_sample = "543991ca8d1c65113dff039b85ae3f9a87f503daec30f46929fd454bc57e5a91"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $pdb_64 = "AntiMalware\\bin\\zam64.pdb"
        $pdb_32 = "AntiMalware\\bin\\zam32.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and any of ($pdb_*)
}

