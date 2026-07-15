rule Windows_VulnDriver_Dpmemio_da264453 {
    meta:
        author = "Elastic Security"
        id = "da264453-c244-4fe0-a111-53d2a930a614"
        fingerprint = "fea1fdaa8b52923868687b3817f1d76e5e962cca91956bf36d843c9617ebdd30"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: ET&T Technology Co.,Ltd., Version: <= 1.0.0.2"
        threat_name = "Windows.VulnDriver.Dpmemio"
        reference_sample = "7cf6881e43337c288b1883fafb234146a450ff94388aee395e05e36202c5afbb"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 45 54 26 54 20 54 65 63 68 6E 6F 6C 6F 67 79 20 43 6F 2E 2C 4C 74 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 64 00 70 00 6D 00 65 00 6D 00 69 00 6F 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x01][\x00-\x00][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "dpmemio.pdb"
        $str2 = "Direct Physical Memory and Port access driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Dpmemio_2abfd5ab {
    meta:
        author = "Elastic Security"
        id = "2abfd5ab-e824-4c84-a0bd-48a1eab30d70"
        fingerprint = "df0cca4b708e876e93e72a69c8bc7eb63a82cfafb1cd9b0d6558577c49c6c941"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: ET&T Technology Co.,Ltd., Version: <= 6.0.6000.16386"
        threat_name = "Windows.VulnDriver.Dpmemio"
        reference_sample = "cd631c54fe1375e4bdd2f63b58bd106066eeee267fc77b3161ceb023ab5fddda"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 45 54 26 54 20 54 65 63 68 6E 6F 6C 6F 67 79 20 43 6F 2E 2C 4C 74 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 64 00 70 00 6D 00 65 00 6D 00 69 00 6F 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x16]|[\x00-\x6f][\x17-\x17])|[\x00-\x00][\x00-\x00][\x06-\x06][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x3f]|[\x00-\x01][\x40-\x40])[\x70-\x70][\x17-\x17]|[\x00-\x00][\x00-\x00][\x06-\x06][\x00-\x00][\x02-\x02][\x40-\x40][\x70-\x70][\x17-\x17])/
        $str1 = "dpmemio.pdb"
        $str2 = "Windows (R) Codename Longhorn DDK driver" wide
        $str3 = "Direct Physical Memory and Port access driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

