rule Windows_VulnDriver_PGRHostControl_a8020d55 {
    meta:
        author = "Elastic Security"
        id = "a8020d55-5532-4ff2-b938-032f6d292643"
        fingerprint = "f519f4e9761fccceb59f8c8014b76d89a83efc50556fbf2d937e6db3b6a81233"
        creation_date = "2026-07-21"
        last_modified = "2026-08-11"
        description = "Subject: FLIR Integrated Imaging Solutions, Inc., Version: <= 2.7.0.0"
        threat_name = "Windows.VulnDriver.PGRHostControl"
        reference_sample = "4b0e9834dd672e4ce81464d8887c71f9a0942140557cd0ad321da9a1aa849959"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 46 4C 49 52 20 49 6E 74 65 67 72 61 74 65 64 20 49 6D 61 67 69 6E 67 20 53 6F 6C 75 74 69 6F 6E 73 2C 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 50 00 47 00 52 00 48 00 6F 00 73 00 74 00 43 00 6F 00 6E 00 74 00 72 00 6F 00 6C 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x06][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x07-\x07][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "PGRHostControl.pdb"
        $str2 = "PGRHostControl.sys" wide
        $str3 = "PGRHostControl Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_PGRHostControl_d47bec66 {
    meta:
        author = "Elastic Security"
        id = "d47bec66-46fe-4684-9bc6-d31f2c277341"
        fingerprint = "960d31f3fb5011aedac87ae1e6c083209de9678fbb55e1cd19dfa0cd9d9271d3"
        creation_date = "2026-07-26"
        last_modified = "2026-08-11"
        description = "Name: PGRHostControl.sys, Version: <= 2.7.0.0"
        threat_name = "Windows.VulnDriver.PGRHostControl"
        reference_sample = "26e62bf4a970332d133623492dcc9887af4c7f510ba7669f7247768cae3239be"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 50 00 47 00 52 00 48 00 6F 00 73 00 74 00 43 00 6F 00 6E 00 74 00 72 00 6F 00 6C 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x06][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x07-\x07][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "PGRHostControl.pdb"
        $str2 = "PGRHostControl.sys" wide
        $str3 = "PGRHostControl Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2 and $str3
}

