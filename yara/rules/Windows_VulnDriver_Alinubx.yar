rule Windows_VulnDriver_Alinubx_fa517f3c {
    meta:
        author = "Elastic Security"
        id = "fa517f3c-1989-4f66-9fd0-aad7fe59856b"
        fingerprint = "00ef420e1f3e40fbaf1140ede75e44d4f8ee9eb9725b83b8b0886cc769ad146c"
        creation_date = "2026-09-09"
        last_modified = "2026-09-25"
        description = "Name: Alinubx.sys, Version: <= 1.3.2.1"
        threat_name = "Windows.VulnDriver.Alinubx"
        reference_sample = "3983e99d8e707782aaf34c7e2d71d998be4d53b340492b8cf579b9ced5c3678f"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 41 00 6C 00 69 00 6E 00 75 00 62 00 78 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x02][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x03-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00]|[\x03-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00]|[\x03-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x02-\x02][\x00-\x00])/
        $str1 = "Alinubx.pdb"
        $str2 = "Alinubx Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2
}

