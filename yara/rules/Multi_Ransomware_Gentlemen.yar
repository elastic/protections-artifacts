rule Multi_Ransomware_Gentlemen_ce5b1d49 {
    meta:
        author = "Elastic Security"
        id = "ce5b1d49-ca2f-4b3b-af34-a3fde469abe4"
        fingerprint = "77b306bab0a3554fad5cd78f6405564ccde37a52a0cb56fed4d9f1da364b1047"
        creation_date = "2026-06-08"
        last_modified = "2026-06-26"
        threat_name = "Multi.Ransomware.Gentlemen"
        reference_sample = "dce2e5cc00eff2493f8ced546dc51f9d5ef78c5ee56805906ec642dfa77a1c70"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $a = "README-GENTLEMEN.txt"
        $b = "gentlemen.bmp"
        $c = "gentlemen_system"
        $d = "TOX CONTACT - RECOVER YOUR FILES" fullword
        $e = "third-party recovery tools are useless" fullword
        $f = "Gentlemen, your network has been encrypted" fullword
        $g = "[+] Lateral movement finished" fullword
        $h = "[+] GPO deployment complete" fullword
        $i = "Error: --fast, --superfast, and --ultrafast cannot be used together."
    condition:
        4 of them
}

