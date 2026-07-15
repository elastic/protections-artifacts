rule Windows_VulnDriver_Dsark_68615e7a {
    meta:
        author = "Elastic Security"
        id = "68615e7a-2494-4d63-b3cb-45cbf29ec874"
        fingerprint = "1d430f5e28125f3920e497338a0d3ebb98764f8a1ce6609ae4995e88102cffdb"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Beijing Qihu Technology Co., Ltd., Version: <= 1.0.0.1221"
        threat_name = "Windows.VulnDriver.Dsark"
        reference_sample = "a22358cb2fb1aa334272deaa24e2280425f9661862b46331cbdc786138ede8be"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 42 65 69 6A 69 6E 67 20 51 69 68 75 20 54 65 63 68 6E 6F 6C 6F 67 79 20 43 6F 2E 2C 20 4C 74 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 64 00 73 00 61 00 72 00 6B 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x03]|[\x00-\xc4][\x04-\x04])[\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\xc5-\xc5][\x04-\x04][\x00-\x00][\x00-\x00])/
        $str1 = "DsArk.pdb"
        $str2 = "Qihoo360 Kernel Mode Driver" wide
        $str3 = "dsark.sys" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

