rule Windows_Hacktool_ProcessHacker_3d01069e {
    meta:
        author = "Elastic Security"
        id = "3d01069e-7afb-4da0-b7ac-23f90db26495"
        fingerprint = "c326aac5b01d90d83b62c207087e88a7bb5f091c3eaa0ead81d807c22756db42"
        creation_date = "2022-03-30"
        last_modified = "2022-03-30"
        threat_name = "Windows.Hacktool.ProcessHacker"
        reference_sample = "70211a3f90376bbc61f49c22a63075d1d4ddd53f0aefa976216c46e6ba39a9f4"
        severity = 100
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = "OriginalFilename\x00kprocesshacker.sys" wide fullword
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name in (filesize - 50KB .. filesize)
}

