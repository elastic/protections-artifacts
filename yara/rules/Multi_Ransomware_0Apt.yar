rule Multi_Ransomware_0Apt_b4df54d2 {
    meta:
        author = "Elastic Security"
        id = "b4df54d2-0cab-430f-bf70-cf7e5a8de5ef"
        fingerprint = "a84e26e81f96e1bae603fba2c50982c7254383b4b1c09364272d76039ec2041f"
        creation_date = "2026-06-02"
        last_modified = "2026-06-26"
        threat_name = "Multi.Ransomware.0Apt"
        reference_sample = "660f0eab11b7fc3db7da4b5c103afba236d77cb9641b158f22852578632125bc"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $a0 = "Wallpaper set ho raha hai" fullword
        $a1 = ".0aptREADME0apt.txt"
        $a2 = "public_key.pemcompany.txt"
        $a3 = "::: 0APT LOCKER :::" fullword
        $a4 = "0APT-KEY" fullword
        $a5 = "README0apt.txt"
        $a6 = "encrypted by \"0apt\" group"
    condition:
        all of them
}

