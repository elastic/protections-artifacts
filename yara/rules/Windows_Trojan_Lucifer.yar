rule Windows_Trojan_Lucifer_ce9d4cc8 {
    meta:
        author = "Elastic Security"
        id = "ce9d4cc8-8f16-4272-a54b-e500d4edea9b"
        fingerprint = "77c86dfbbd4fb113dabf6016f22d879322357de8ea4a8a598ce9fba761419c55"
        creation_date = "2022-02-17"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.Lucifer"
        reference_sample = "1c63d83084d84d9269e3ce164c2f28438eadf723d46372064fe509fb08f94c3c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 00 0A 28 47 00 00 0A 00 DE 02 00 DC 00 28 09 00 00 06 02 6F 48 }
    condition:
        all of them
}

