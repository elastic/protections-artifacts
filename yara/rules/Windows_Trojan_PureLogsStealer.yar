rule Windows_Trojan_PureLogsStealer_8ea443f9 {
    meta:
        author = "Elastic Security"
        id = "8ea443f9-caf7-4edd-87ba-be54d62f8d42"
        fingerprint = "d0e81a3671075092db3d83dc9256d4e7b166e9e87d7116721d0b716bdb015b12"
        creation_date = "2026-06-18"
        last_modified = "2026-07-20"
        threat_name = "Windows.Trojan.PureLogsStealer"
        reference_sample = "07cd03e2082bcb0b890cc59ce4c770d1a095ac6f1ae9cf999f5542555c56f841"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "SendDiscordAsync" ascii fullword
        $str2 = "SendCryptoWalletAsync" ascii fullword
        $str3 = "CollectAndSendAllAsync" ascii fullword
        $str4 = "/filesearch/req" wide fullword
        $str5 = "/filesearch/res" wide fullword
        $str6 = "/chunk/data" wide fullword
        $str7 = "/chunk/start" wide fullword
    condition:
        3 of them
}

