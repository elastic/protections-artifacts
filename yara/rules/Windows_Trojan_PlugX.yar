rule Windows_Trojan_PlugX_5f3844ff {
    meta:
        author = "Elastic Security"
        id = "5f3844ff-2da6-48b4-9afb-343149af03ac"
        fingerprint = "5365e6978ffca67e232165bca7bcdc5064abd5c589e49e19aa640f59dd5285ab"
        creation_date = "2023-08-28"
        last_modified = "2023-09-20"
        threat_name = "Windows.Trojan.PlugX"
        reference_sample = "a823380e46878dfa8deb3ca0dc394db1db23bb2544e2d6e49c0eceeffb595875"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "EAddr:0x%p"
        $a2 = "Host: [%s:%d]" ascii fullword
        $a3 = "CONNECT %s:%d HTTP/1.1" ascii fullword
        $a4 = "%4.4d-%2.2d-%2.2d %2.2d:%2.2d:%2.2d:" wide fullword
        $a5 = "\\bug.log" wide fullword
    condition:
        all of them
}

