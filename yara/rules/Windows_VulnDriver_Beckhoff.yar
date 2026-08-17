rule Windows_VulnDriver_Beckhoff_882be601 {
    meta:
        author = "Elastic Security"
        id = "882be601-4112-41a8-ab1f-ea61e8683fa8"
        fingerprint = "3dfa8155ab04ba428a26dd46047668d4af50e698cd62dcbdb1f06166f6104563"
        creation_date = "2026-07-26"
        last_modified = "2026-08-11"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher, Version: <= 3.1.0.2355"
        threat_name = "Windows.VulnDriver.Beckhoff"
        reference_sample = "d89938a469e8e4b429507522b5a52cb6f87c50f559f22f3042921631b768e59a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x03-\x03][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x08]|[\x00-\x32][\x09-\x09])[\x00-\x00][\x00-\x00]|[\x01-\x01][\x00-\x00][\x03-\x03][\x00-\x00][\x33-\x33][\x09-\x09][\x00-\x00][\x00-\x00])/
        $str1 = "TcRouter.pdb"
        $str2 = "\\Device\\ROUTER_IO_COMPLETE"
        $str3 = "GetRouterFuncTable"
        $str4 = "Beckhoff TwinCAT" wide
        $str5 = "TwinCAT Router Server" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1 and $str2 and $str3 and $str4 and $str5
}

