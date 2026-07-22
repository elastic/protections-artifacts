rule Windows_VulnDriver_LenovoDiag_e7e5a5fc {
    meta:
        author = "Elastic Security"
        id = "e7e5a5fc-e23e-4b16-acb0-c7994e44d1b1"
        fingerprint = "394994fa4f92a95952fe385a94e3e57ef1ceaaefdf6e7f819c274809433706ae"
        creation_date = "2022-11-09"
        last_modified = "2026-07-20"
        description = "Name: LenovoDiagnosticsDriver.sys, Version: <= 1.65535.65535.65535"
        threat_name = "Windows.VulnDriver.LenovoDiag"
        reference_sample = "f05b1ee9e2f6ab704b8919d5071becbce6f9d0f9d0ba32a460c41d5272134abe"
        severity = 100
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4C 00 65 00 6E 00 6F 00 76 00 6F 00 44 00 69 00 61 00 67 00 6E 00 6F 00 73 00 74 00 69 00 63 00 73 00 44 00 72 00 69 00 76 00 65 00 72 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\xff][\x00-\xff])([\x00-\x01][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\xff][\x00-\xff])([\x00-\x00][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\xfe][\x00-\xff])([\x00-\x01][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\xff][\x00-\xff])([\x00-\x01][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xfe][\x00-\xff]))/
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version
}

