rule Windows_Rootkit_Tdevflt_ebf2a53f {
    meta:
        author = "Elastic Security"
        id = "ebf2a53f-d26e-428f-80a0-1ff3f2d6ddb6"
        fingerprint = "14c50a1fa4e4ddcfc9294f6abc5add04cb4ba495ae0dd4ea4908307c6c535ab1"
        creation_date = "2026-07-26"
        last_modified = "2026-08-11"
        description = "Subject: Shanghai easy kradar Information Consulting Co. Ltd., Version: <= 8.2.2.49708"
        threat_name = "Windows.Rootkit.Tdevflt"
        reference_sample = "8284c8676cc22c4b2e66826ac16986da7ddecba1f2776b16771be17bfdc45dc2"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 68 61 6E 67 68 61 69 20 65 61 73 79 20 6B 72 61 64 61 72 20 49 6E 66 6F 72 6D 61 74 69 6F 6E 20 43 6F 6E 73 75 6C 74 69 6E 67 20 43 6F 2E 20 4C 74 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 74 00 64 00 65 00 76 00 66 00 6C 00 74 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x07][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x01][\x00-\x00][\x08-\x08][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x08-\x08][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00]|[\x02-\x02][\x00-\x00][\x08-\x08][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\xc1]|[\x00-\x2b][\xc2-\xc2])[\x02-\x02][\x00-\x00]|[\x02-\x02][\x00-\x00][\x08-\x08][\x00-\x00][\x2c-\x2c][\xc2-\xc2][\x02-\x02][\x00-\x00])/
        $str1 = { 43 00 6F 00 72 00 74 00 65 00 78 00 20 00 58 00 44 00 52 00 22 21 20 00 41 00 64 00 76 00 61 00 6E 00 63 00 65 00 64 00 20 00 45 00 6E 00 64 00 70 00 6F 00 69 00 6E 00 74 00 20 00 50 00 72 00 6F 00 74 00 65 00 63 00 74 00 69 00 6F 00 6E 00 }
        $str2 = "Cortex XDR PnP Device Filter Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

