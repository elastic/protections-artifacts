rule Windows_VulnDriver_NeoVMDrv_56809715 {
    meta:
        author = "Elastic Security"
        id = "56809715-3f45-40f2-8e8f-fbfa0fc46dc0"
        fingerprint = "e0287d50f9ad6bafc29bec73d539771c38e8a42c9ee036b27132ab7e7439d3fe"
        creation_date = "2026-08-06"
        last_modified = "2026-08-17"
        threat_name = "Windows.VulnDriver.NeoVMDrv"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $version1 = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x0d]|[\x00-\x14][\x0e-\x0e])[\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x15-\x15][\x0e-\x0e][\x00-\x00][\x00-\x00])/
        $version2 = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x0a]|[\x00-\x1a][\x0b-\x0b])[\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x1b-\x1b][\x0b-\x0b][\x00-\x00][\x00-\x00])/
        $device_name = "\\DosDevices\\DCRCVDRV_U" ascii wide
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 44 00 43 00 52 00 43 00 56 00 44 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $pdb = "DCRCVDrv64.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $device_name and $pdb and $original_file_name and ($version1 or $version2)
}

