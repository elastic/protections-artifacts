rule Windows_VulnDriver_Psmounterex_e3f3ba72 {
    meta:
        author = "Elastic Security"
        id = "e3f3ba72-889a-4309-83d6-cf291d55ecb9"
        fingerprint = "aae32a20ab72aff7e05167a8c24bc0420a27761d65368dea689566a671950adc"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Name: psmounterex.sys, Version: <= 6.1.865.0"
        threat_name = "Windows.VulnDriver.Psmounterex"
        reference_sample = "6a04f0fcb89a7d9810e456b8748d962cccc4caab02795c9cdacaab7f827bc398"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 70 00 73 00 6D 00 6F 00 75 00 6E 00 74 00 65 00 72 00 65 00 78 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x02]|[\x00-\x60][\x03-\x03])|[\x01-\x01][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\x00][\x00-\x00][\x61-\x61][\x03-\x03])/
        $str1 = "PSMounterEx.pdb"
        $str2 = "IOCTL_PSMOUNTER_QUERY_PERFORMANCE_DATA"
        $str3 = "IOCTL_VOLUME_SUPPORTS_ONLINE_OFFLINE"
        $str4 = "\\DosDevices\\%c:"
        $str5 = "PSMounterEx" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2 and $str3 and $str4 and $str5
}

