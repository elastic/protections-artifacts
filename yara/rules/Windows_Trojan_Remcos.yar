rule Windows_Trojan_Remcos_b296e965 {
    meta:
        author = "Elastic Security"
        id = "b296e965-a99e-4446-b969-ba233a2a8af4"
        fingerprint = "a5267bc2dee28a3ef58beeb7e4a151699e3e561c16ce0ab9eb27de33c122664d"
        creation_date = "2021-06-10"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Remcos"
        reference_sample = "0ebeffa44bd1c3603e30688ace84ea638fbcf485ca55ddcfd6fbe90609d4f3ed"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "Remcos restarted by watchdog!" ascii fullword
        $a2 = "Mutex_RemWatchdog" ascii fullword
        $a3 = "%02i:%02i:%02i:%03i"
        $a4 = "* Remcos v" ascii fullword
    condition:
        2 of them
}

