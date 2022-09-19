rule Windows_Trojan_Hawkeye_77c36ace {
    meta:
        author = "Elastic Security"
        id = "77c36ace-3857-43f8-a6de-596ba7964b6f"
        fingerprint = "c9a1c61b4fa78c46d493e1b307e9950bd714ba4e5a6249f15a3b86a74b7638e5"
        creation_date = "2021-08-16"
        last_modified = "2021-10-04"
        threat_name = "Windows.Trojan.Hawkeye"
        reference_sample = "28e28025060f1bafd4eb96c7477cab73497ca2144b52e664b254c616607d94cd"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "Logger - Key Recorder - [" wide fullword
        $a2 = "http://whatismyipaddress.com/" wide fullword
        $a3 = "Keylogger Enabled: " wide fullword
        $a4 = "LoadPasswordsSeaMonkey" wide fullword
        $a5 = "\\.minecraft\\lastlogin" wide fullword
    condition:
        all of them
}

