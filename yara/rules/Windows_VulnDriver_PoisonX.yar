rule Windows_VulnDriver_PoisonX_79e368e7 {
    meta:
        author = "Elastic Security"
        id = "79e368e7-27f8-484d-a4ed-7786a441129e"
        fingerprint = "edc391c48b72781427b36c7017d1149e4b19d8fc3d2a00a1a9f6001994a35035"
        creation_date = "2026-04-06"
        last_modified = "2026-07-20"
        threat_name = "Windows.VulnDriver.PoisonX"
        reference_sample = "a5035cbd6c31616288aa66d98e5a25441ee38651fb5f330676319f921bb816a4"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $pdb = "D:\\Build\\PoisonX\\Hide\\x64\\Release\\Hide.pdb" ascii fullword
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $pdb
}

