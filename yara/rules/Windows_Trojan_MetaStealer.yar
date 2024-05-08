rule Windows_Trojan_MetaStealer_f94e2464 {
    meta:
        author = "Elastic Security"
        id = "f94e2464-b41a-46fd-89c1-335aa8c14425"
        fingerprint = "fb35feaf8e2d0994d022da1c8e872dc8b05b04e25ab6fed2ed1997267edfccd9"
        creation_date = "2024-03-27"
        last_modified = "2024-05-08"
        threat_name = "Windows.Trojan.MetaStealer"
        reference_sample = "14ca15c0751207103c38f1a2f8fdc73e5dd3d58772f6e5641e54e0c790ecd132"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $string1 = "AvailableLanguages" fullword
        $string2 = "GetGraphicCards" fullword
        $string3 = "GetVs" fullword
        $string4 = "GetSerialNumber" fullword
        $string5 = "net.tcp://" wide
        $string6 = "AntivirusProduct|AntiSpyWareProduct|FirewallProduct" wide
        $string7 = "wallet.dat" wide
        $string8 = "[A-Za-z\\d]{24}\\.[\\w-]{6}\\.[\\w-]{27}" wide
        $string9 = "Software\\Valve\\Steam" wide
        $string10 = "{0}\\FileZilla\\recentservers.xml" wide
        $string11 = "{0}\\FileZilla\\sitemanager.xml" wide
        $string12 = "([a-zA-Z0-9]{1000,1500})" wide
        $string13 = "\\qemu-ga.exe" wide
        $string14 = "metaData" wide
        $string15 = "%DSK_23%" wide
        $string16 = "CollectMemory" fullword
    condition:
        all of them
}

