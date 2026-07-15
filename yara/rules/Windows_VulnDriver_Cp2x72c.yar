rule Windows_VulnDriver_Cp2x72c_fcd73a9f {
    meta:
        author = "Elastic Security"
        id = "fcd73a9f-c34e-4d22-a1ff-2d3f90a7b7e8"
        fingerprint = "7953974120106fa7393b4d2b83c234ccbce124ddc0ec4c7c848b647a3327131f"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Name: CP2X72C.SYS, Version: <= 3.2.30.0"
        threat_name = "Windows.VulnDriver.Cp2x72c"
        reference_sample = "10272aff45a602dc2bc0223f17ffe6595d829f001225ae578af6080c01fdb75d"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 43 00 50 00 32 00 58 00 37 00 32 00 43 00 2E 00 53 00 59 00 53 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x01][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x1d][\x00-\x00]|[\x02-\x02][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\x00][\x00-\x00][\x1e-\x1e][\x00-\x00])/
        $str1 = "CP2X72C.pdb"
        $str2 = "GPC-2X72C DIO-BM(PCI/C-PCI)" wide
        $str3 = "GPC-2X72C I/O Module Device Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2 and $str3
}

