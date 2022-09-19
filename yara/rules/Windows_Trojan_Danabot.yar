rule Windows_Trojan_Danabot_6f3dadb2 {
    meta:
        author = "Elastic Security"
        id = "6f3dadb2-3283-4333-8143-1265721d2221"
        fingerprint = "387e3fb3c3f625c8b5e42052c126ce4dbb7de3a7de6b68addf0a0777b9d3b504"
        creation_date = "2021-08-15"
        last_modified = "2021-10-04"
        threat_name = "Windows.Trojan.Danabot"
        reference_sample = "716e5a3d29ff525aed30c18061daff4b496f3f828ba2ac763efd857062a42e96"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "%s.dll" ascii fullword
        $a2 = "del_ini://Main|Password|" wide fullword
        $a3 = "S-Password.txt" wide fullword
        $a4 = "BiosTime:" wide fullword
        $a5 = "%lu:%s:%s:%d:%s" ascii fullword
        $a6 = "DNS:%s" ascii fullword
        $a7 = "THttpInject&" ascii fullword
        $a8 = "TCookies&" ascii fullword
    condition:
        all of them
}

