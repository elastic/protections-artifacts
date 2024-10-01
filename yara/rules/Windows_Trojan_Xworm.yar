rule Windows_Trojan_Xworm_732e6c12 {
    meta:
        author = "Elastic Security"
        id = "732e6c12-9ee0-4d04-a6e4-9eef874e2716"
        fingerprint = "afbef8e590105e16bbd87bd726f4a3391cd6a4489f7a4255ba78a3af761ad2f0"
        creation_date = "2023-04-03"
        last_modified = "2023-04-23"
        threat_name = "Windows.Trojan.Xworm"
        reference_sample = "bf5ea8d5fd573abb86de0f27e64df194e7f9efbaadd5063dee8ff9c5c3baeaa2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "startsp" ascii wide fullword
        $str2 = "injRun" ascii wide fullword
        $str3 = "getinfo" ascii wide fullword
        $str4 = "Xinfo" ascii wide fullword
        $str5 = "openhide" ascii wide fullword
        $str6 = "WScript.Shell" ascii wide fullword
        $str7 = "hidefolderfile" ascii wide fullword
    condition:
        all of them
}

rule Windows_Trojan_Xworm_b7d6eaa8 {
    meta:
        author = "Elastic Security"
        id = "b7d6eaa8-f4e6-42e6-95b2-ce67f513d6c5"
        fingerprint = "0c68cb5c8425cccc6af66c33a14e14e5f16d91835209bd38cddf38fad07a40fa"
        creation_date = "2024-09-10"
        last_modified = "2024-09-30"
        threat_name = "Windows.Trojan.Xworm"
        reference_sample = "6fc4ff3f025545f7e092408b035066c1138253b972a2e9ef178e871d36f03acd"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "XWorm V" wide
        $str2 = "XLogger" ascii fullword
        $str3 = "<Xwormmm>" wide fullword
        $str4 = "ActivatePong" ascii fullword
        $str5 = "ReportWindow" ascii fullword
        $str6 = "ConnectServer" ascii fullword
    condition:
        4 of them
}

