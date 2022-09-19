rule Windows_Trojan_AveMaria_31d2bce9 {
    meta:
        author = "Elastic Security"
        id = "31d2bce9-3266-447b-9a2d-57cf11a0ff1f"
        fingerprint = "8f75e2d8308227a42743168deb021de18ad485763fd257991c5e627c025c30c0"
        creation_date = "2021-05-30"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.AveMaria"
        reference_sample = "5767bca39fa46d32a6cb69ef7bd1feaac949874768dac192dbf1cf43336b3d7b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "cmd.exe /C ping 1.2.3.4 -n 2 -w 1000 > Nul & Del /f /q " ascii fullword
        $a2 = "SMTP Password" wide fullword
        $a3 = "select signon_realm, origin_url, username_value, password_value from logins" ascii fullword
        $a4 = "Elevation:Administrator!new:{3ad05575-8857-4850-9277-11b85bdb8e09}" wide fullword
        $a5 = "for /F \"usebackq tokens=*\" %%A in (\"" wide fullword
        $a6 = "\\Torch\\User Data\\Default\\Login Data" wide fullword
        $a7 = "/n:%temp%\\ellocnak.xml" wide fullword
        $a8 = "\"os_crypt\":{\"encrypted_key\":\"" wide fullword
        $a9 = "Hey I'm Admin" wide fullword
        $a10 = "\\logins.json" wide fullword
        $a11 = "Accounts\\Account.rec0" ascii fullword
        $a12 = "warzone160" ascii fullword
        $a13 = "Ave_Maria Stealer OpenSource github Link: https://github.com/syohex/java-simple-mine-sweeper" wide fullword
    condition:
        8 of ($a*)
}

