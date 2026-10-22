rule MacOS_Trojan_CloudSyncD_afad16ad {
    meta:
        author = "Elastic Security"
        id = "afad16ad-48cf-4afc-91f0-afb94e8bde62"
        fingerprint = "bd05e623efce4e0f347f93011b749a5ae946b9fc007a545555aeb18f3434c03c"
        creation_date = "2026-10-07"
        last_modified = "2026-10-19"
        threat_name = "MacOS.Trojan.CloudSyncD"
        reference_sample = "929f43701be4cde41eddb73e25df9056978f1683bc839826a5391f571c79b8d4"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $str1 = "cloudsync_impl"
        $str2 = "launch_embedded_gate"
        $str3 = "save_local_password"
        $str4 = "create_auth_json"
        $str5 = "claim_installer_lock"
        $seq1 = { B0 01 0F B6 4D EF 84 C0 74 20 80 F9 FF 75 1B F6 03 01 75 07 66 C7 03 00 00 EB 0F }
        $seq2 = { D7 19 BF 57 E6 5B A0 9D E1 BA CD B1 82 C9 91 18 ED AF D5 18 FD 3A 4A 97 97 BC AD 22 1A DB 81 51 }
    condition:
        4 of ($str*) or 2 of ($seq*)
}

