rule Windows_Ransomware_Stop_1e8d48ff {
    meta:
        author = "Elastic Security"
        id = "1e8d48ff-e0ab-478d-8268-a11f2e87ab79"
        fingerprint = "715888e3e13aaa33f2fd73beef2c260af13e9726cb4b43d349333e3259bf64eb"
        creation_date = "2021-06-10"
        last_modified = "2021-08-23"
        threat_name = "Windows.Ransomware.Stop"
        reference_sample = "821b27488f296e15542b13ac162db4a354cbf4386b6cd40a550c4a71f4d628f3"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = "E:\\Doc\\My work (C++)\\_Git\\Encryption\\Release\\encrypt_win_api.pdb" ascii fullword
        $b = { 68 FF FF FF 50 FF D3 8D 85 78 FF FF FF 50 FF D3 8D 85 58 FF }
    condition:
        any of them
}

