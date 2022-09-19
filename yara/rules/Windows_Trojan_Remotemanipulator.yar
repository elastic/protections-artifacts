rule Windows_Trojan_Remotemanipulator_9ec52153 {
    meta:
        author = "Elastic Security"
        id = "9ec52153-3b62-432d-b87c-895035df1a46"
        fingerprint = "02220e8af70ecffb3a7585f756c59ef5d9e17e6690c36d6bffc458e1d17dbd0c"
        creation_date = "2021-09-02"
        last_modified = "2022-01-13"
        threat_name = "Windows.Trojan.Remotemanipulator"
        reference_sample = "1dd15c830c0a159b53ed21b8c2ce1b7e8093256368d7b96c1347c6851ee6c4f6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "killself.bat" wide fullword
        $a2 = "rutserv.exe" wide fullword
        $a3 = "rfusclient.exe" wide fullword
        $a4 = "install.log" wide fullword
        $a5 = "Unable to create Agent's path." wide fullword
    condition:
        all of them
}

