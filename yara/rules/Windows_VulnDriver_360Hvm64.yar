rule Windows_VulnDriver_360Hvm64_bf27076b {
    meta:
        author = "Elastic Security"
        id = "bf27076b-c3fd-4635-b447-644cc312e9e9"
        fingerprint = "62f2c932e794418055ea39a42b27463526c53f60e699b8cce424779b9697ce85"
        creation_date = "2026-07-21"
        last_modified = "2026-08-11"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher, Version: <= 2.0.0.1207"
        threat_name = "Windows.VulnDriver.360Hvm64"
        reference_sample = "f89d5d95b8a59e6d5e50a49217f83d080e4eaf4bb77b80d8f38cd915640ba124"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 33 00 36 00 30 00 48 00 76 00 6D 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x03]|[\x00-\xb6][\x04-\x04])[\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\xb7-\xb7][\x04-\x04][\x00-\x00][\x00-\x00])/
        $str1 = "360Hvm64" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1
}

