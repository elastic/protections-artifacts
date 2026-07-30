rule Windows_VulnDriver_Usbxhci_8d0a6564 {
    meta:
        author = "Elastic Security"
        id = "8d0a6564-29ab-4b7b-be39-938b076c7e00"
        fingerprint = "1a3edd10cb865fe1d4d1bc50cf65b71422d6957aa65d88e47e8a4307aa55016b"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Shenzhen Jinxian Technology Co., Ltd., Version: <= 6.2.9200.22099"
        threat_name = "Windows.VulnDriver.Usbxhci"
        reference_sample = "290bc7822da41f0b5580b27c8d14a2a5c3fbe3e4b6921957b134efc6beeb0aeb"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 68 65 6E 7A 68 65 6E 20 4A 69 6E 78 69 61 6E 20 54 65 63 68 6E 6F 6C 6F 67 79 20 43 6F 2E 2C 20 4C 74 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 75 00 73 00 62 00 78 00 68 00 63 00 69 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x01][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x22]|[\x00-\xef][\x23-\x23])|[\x02-\x02][\x00-\x00][\x06-\x06][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x55]|[\x00-\x52][\x56-\x56])[\xf0-\xf0][\x23-\x23]|[\x02-\x02][\x00-\x00][\x06-\x06][\x00-\x00][\x53-\x53][\x56-\x56][\xf0-\xf0][\x23-\x23])/
        $str1 = "usbxhci.pdb"
        $str2 = { 4D 00 69 00 63 00 72 00 6F 00 73 00 6F 00 66 00 74 00 AE 00 20 00 57 00 69 00 6E 00 64 00 6F 00 77 00 73 00 AE 00 20 00 4F 00 70 00 65 00 72 00 61 00 74 00 69 00 6E 00 67 00 20 00 53 00 79 00 73 00 74 00 65 00 6D 00 }
        $str3 = "USB XHCI Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

