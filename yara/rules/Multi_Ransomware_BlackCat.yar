rule Multi_Ransomware_BlackCat_aaf312c3 {
    meta:
        author = "Elastic Security"
        id = "aaf312c3-47b4-4dab-b7fc-8a2ac9883772"
        fingerprint = "a836eca69ee7ae0afa2ed7035c699065482958700c3e9a9624c7d720e8551654"
        creation_date = "2022-02-02"
        last_modified = "2022-08-16"
        threat_name = "Multi.Ransomware.BlackCat"
        reference_sample = "0c6f444c6940a3688ffc6f8b9d5774c032e3551ebbccb64e4280ae7fc1fac479"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $a = { EF D9 F3 0F 7F 14 3B F3 0F 7F 5C 3B 10 83 C7 20 39 F8 75 D0 8B }
    condition:
        all of them
}

rule Multi_Ransomware_BlackCat_00e525d7 {
    meta:
        author = "Elastic Security"
        id = "00e525d7-a8a6-475f-89ad-607c452aea1e"
        fingerprint = "631e30b8b51a5c0a0e91e8c09968663192569005b8bffff9f0474749788e9d57"
        creation_date = "2022-02-02"
        last_modified = "2022-08-16"
        threat_name = "Multi.Ransomware.BlackCat"
        reference_sample = "0c6f444c6940a3688ffc6f8b9d5774c032e3551ebbccb64e4280ae7fc1fac479"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $a1 = "ata\",\"boot\",\"config.msi\",\"google\",\"perflogs\",\"appdata\",\"windows.old\"],\"exclude_file_names\":[\"desktop.ini\",\"aut"
        $a2 = "locker::core::windows::processvssadmin.exe delete shadows /all /quietshadow_copy::remove_all=" ascii fullword
        $a3 = "\\\\.\\pipe\\__rust_anonymous_pipe1__." ascii fullword
        $a4 = "--bypass-p-p--bypass-path-path --no-prop-servers \\\\" ascii fullword
    condition:
        all of them
}

rule Multi_Ransomware_BlackCat_c4b043e6 {
    meta:
        author = "Elastic Security"
        id = "c4b043e6-ff5f-4492-94e3-fd688d690738"
        fingerprint = "3e89858e90632ad5f4831427bd630252113b735c51f7a1aa1eab8ba6e4c16f18"
        creation_date = "2022-09-12"
        last_modified = "2022-09-29"
        threat_name = "Multi.Ransomware.BlackCat"
        reference_sample = "45b8678f74d29c87e2d06410245ab6c2762b76190594cafc9543fb9db90f3d4f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $a = { 28 4C 8B 60 08 4C 8B 68 10 0F 10 40 28 0F 29 44 24 10 0F 10 }
    condition:
        all of them
}

