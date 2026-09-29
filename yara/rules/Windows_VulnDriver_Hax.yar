rule Windows_VulnDriver_Hax_82db9472 {
    meta:
        author = "Elastic Security"
        id = "82db9472-9ed6-4176-80d2-906764d60215"
        fingerprint = "295d16860dbc0888f657cc4897cde09f59aa0ad0feb64c51483c661e24403d23"
        creation_date = "2026-09-09"
        last_modified = "2026-09-25"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher, Version: <= 7.6.5.3"
        threat_name = "Windows.VulnDriver.Hax"
        reference_sample = "6272aa047c054424f30f09b9ffbc543f4084fa4ac878c7b90d29fbc0502e0e33"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 68 00 61 00 78 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x05][\x00-\x00][\x07-\x07][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x06-\x06][\x00-\x00][\x07-\x07][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x04][\x00-\x00]|[\x06-\x06][\x00-\x00][\x07-\x07][\x00-\x00][\x00-\x02][\x00-\x00][\x05-\x05][\x00-\x00]|[\x06-\x06][\x00-\x00][\x07-\x07][\x00-\x00][\x03-\x03][\x00-\x00][\x05-\x05][\x00-\x00])/
        $str1 = "GoogleHaxm.pdb"
        $str2 = "IOCTL_ADD_RAMBLOCK"
        $str3 = "IOCTL_PROTECT_RAM"
        $str4 = "HAXM_Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4
}

rule Windows_VulnDriver_Hax_804523ba {
    meta:
        author = "Elastic Security"
        id = "804523ba-6d95-44cb-957f-120b3fe2be79"
        fingerprint = "b349764241570bc98b0c8a5c3f7c5e5f083a991f5a9db6a7be795a57e9b21b37"
        creation_date = "2026-09-09"
        last_modified = "2026-09-25"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher, Version: <= 7.7.0.0"
        threat_name = "Windows.VulnDriver.Hax"
        reference_sample = "e6d2868eeaaf315c4f022844a2fe55dff7f76445c057b3057024e6fd3365d020"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 68 00 61 00 78 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x06][\x00-\x00][\x07-\x07][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x07-\x07][\x00-\x00][\x07-\x07][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "IntelHaxm.pdb"
        $str2 = "IOCTL_ADD_RAMBLOCK"
        $str3 = "IOCTL_PROTECT_RAM"
        $str4 = "HAXM_Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4
}

