rule Windows_Infostealer_Strela_0dc3e4a1 {
    meta:
        author = "Elastic Security"
        id = "0dc3e4a1-13ac-4461-aac9-896f9e30d84b"
        fingerprint = "517b11ee532ecc6beba5a705618e4a25869abb33fd4ba58e1f956fad95e20ac3"
        creation_date = "2024-03-25"
        last_modified = "2024-05-08"
        threat_name = "Windows.Infostealer.Strela"
        reference_sample = "e6991b12e86629b38e178fef129dfda1d454391ffbb236703f8c026d6d55b9a1"
        severity = 100
        arch_context = "x86"
        scan_context = "memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $s1 = "strela" fullword
        $s2 = "/server.php" fullword
        $s3 = "%s%s\\key4.db" fullword
        $s4 = "%s%s\\logins.json" fullword
        $old_pdb = "Projects\\StrelaDLLCompile\\Release\\StrelaDLLCompile.pdb" fullword
    condition:
        all of ($s*) or $old_pdb
}

