rule Windows_Trojan_DarkGate_fa1f1338 {
    meta:
        author = "Elastic Security"
        id = "fa1f1338-c920-4db9-a7ec-cd11d7e1558b"
        fingerprint = "182481e23eb10f0a8b7d0d536e2d8d36ab5e51fd798caebff4d38d55b5549244"
        creation_date = "2023-12-14"
        last_modified = "2024-01-12"
        threat_name = "Windows.Trojan.DarkGate"
        reference_sample = "1fce9ee9254dd0641387cc3b6ea5f6a60f4753132c20ca03ce4eed2aa1042876"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str0 = "DarkGate has recovered from a Critical error"
        $str1 = "Executing DarkGate inside the new desktop..."
        $str2 = "Restart Darkgate "
    condition:
        2 of them
}

