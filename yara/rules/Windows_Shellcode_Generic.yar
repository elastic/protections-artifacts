rule Windows_Shellcode_Generic_8c487e57 {
    meta:
        author = "Elastic Security"
        id = "8c487e57-4b8c-488e-a1d9-786ff935fd2c"
        fingerprint = "834caf96192a513aa93ac48fb8d2f3326bf9f08acaf7a27659f688b26e3e57e4"
        creation_date = "2022-05-23"
        last_modified = "2022-07-18"
        threat_name = "Windows.Shellcode.Generic"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { FC E8 89 00 00 00 60 89 E5 31 D2 64 8B 52 30 8B 52 0C 8B 52 14 8B 72 28 0F B7 4A 26 31 FF 31 C0 }
    condition:
        all of them
}

