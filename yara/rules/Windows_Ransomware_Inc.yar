rule Windows_Ransomware_Inc_8f212220 {
    meta:
        author = "Elastic Security"
        id = "8f212220-c2e5-48b7-801d-dff2e7293908"
        fingerprint = "b3505a27e451bc24dad0d9ba8aea36b8433c965a0fa926fc674bc3458f47c025"
        creation_date = "2026-06-09"
        last_modified = "2026-06-26"
        threat_name = "Windows.Ransomware.Inc"
        reference_sample = "ef8b3b7bd487f9b949cb8cf33892eb7b687cf93d24c6934e0bec2743ad953166"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = "Couldn't delete shadow copies from" ascii wide fullword
        $b = "Count of printers: %d\n" ascii wide fullword
        $c = "Success! Closing printer: %s\n" ascii wide fullword
        $d = "Encrypting file: %s\n" ascii wide fullword
        $e = "Found drive: %s\n" ascii wide fullword
        $f = "Loading hidden drives...\n" ascii wide fullword
        $g = "--file <FILE>" ascii wide fullword
        $h = "--safe-mode" ascii wide fullword
        $i = "Starting full encryption in 5s" ascii wide fullword
    condition:
        4 of them
}

