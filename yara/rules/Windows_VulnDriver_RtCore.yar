rule Windows_VulnDriver_RtCore_4eeb2ce5 {
    meta:
        author = "Elastic Security"
        id = "4eeb2ce5-e481-4e9c-beda-2b01f259ed96"
        fingerprint = "cebca7dc572afccf4eb600980b9cbaef0878213f91c04b4605a0cf4d0e5e541f"
        creation_date = "2022-04-04"
        last_modified = "2022-08-30"
        threat_name = "Windows.VulnDriver.RtCore"
        reference_sample = "01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0bf7a695862444af32e87f1fd"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "\\Device\\RTCore64" wide fullword
        $str2 = "Kaspersky Lab Anti-Rootkit Monitor Driver" wide fullword
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1 and not $str2
}

