rule Windows_Trojan_Winos_464b8a2e {
    meta:
        author = "Elastic Security"
        id = "464b8a2e-851c-45eb-89fe-ea265b01514a"
        fingerprint = "e626d858981a4f44d63d61f124413e617e1b63755b10dd3089805758bc809b01"
        creation_date = "2025-05-08"
        last_modified = "2025-05-27"
        threat_name = "Windows.Trojan.Winos"
        reference_sample = "ea57f741eeb76fb77cd84fbb1ff7b33d00772b751d20cbc0ce8dc3278db141af"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "CLSID\\{%.8X-%.4X-%.4X-%.2X%.2X-%.2X%.2X%.2X%.2X%.2X%.2X}" wide fullword
        $a2 = "d33f351a4aeea5e608853d1a56661059" wide fullword
        $a3 = "%s-%04d%02d%02d-%02d%02d%02d.dmp" wide fullword
        $a4 = "Windows\\System32\\tracerpt.exe" wide fullword
        $a5 = "Software\\Tencent\\Plugin\\VAS" wide fullword
        $a6 = "onlyloadinmyself" wide fullword
        $a7 = "IpDatespecial" wide fullword
        $a8 = "IpDates_info" wide fullword
        $a9 = "Console\\0" wide fullword
        $a10 = "Console\\1" wide fullword
    condition:
        4 of them
}

