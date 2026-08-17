rule Windows_VulnDriver_Cyvrlpc_de1fea97 {
    meta:
        author = "Elastic Security"
        id = "de1fea97-aaa2-4890-9964-4f95f2f75616"
        fingerprint = "8fa509fbcb7e4c78dd4ffc0035a618595078d779315b2a20f4e81605d1e382fb"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: FEI XIAO, Version: <= 8.2.2.49708"
        threat_name = "Windows.VulnDriver.Cyvrlpc"
        reference_sample = "2cd7a0c4e8d24404c92e4ed8539b2136028a8ca663f3432e417b00665493e13f"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 46 45 49 20 58 49 41 4F }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 63 00 79 00 76 00 72 00 6C 00 70 00 63 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x07][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x01][\x00-\x00][\x08-\x08][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x08-\x08][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00]|[\x02-\x02][\x00-\x00][\x08-\x08][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\xc1]|[\x00-\x2b][\xc2-\xc2])[\x02-\x02][\x00-\x00]|[\x02-\x02][\x00-\x00][\x08-\x08][\x00-\x00][\x2c-\x2c][\xc2-\xc2][\x02-\x02][\x00-\x00])/
        $str1 = { 43 00 6F 00 72 00 74 00 65 00 78 00 20 00 58 00 44 00 52 00 22 21 20 00 41 00 64 00 76 00 61 00 6E 00 63 00 65 00 64 00 20 00 45 00 6E 00 64 00 70 00 6F 00 69 00 6E 00 74 00 20 00 50 00 72 00 6F 00 74 00 65 00 63 00 74 00 69 00 6F 00 6E 00 }
        $str2 = "Cortex XDR LPC Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Cyvrlpc_f121cb09 {
    meta:
        author = "Elastic Security"
        id = "f121cb09-64e1-41c0-ba77-fd615d3c3209"
        fingerprint = "e0c11da1e4ac7804cd88df9ed6ca8452bbcb04e2864e3b468c4f944cd485d1e3"
        creation_date = "2026-07-22"
        last_modified = "2026-08-11"
        description = "Subject: 长沙恒祥信息技术有限公司, Version: <= 8.2.2.49708"
        threat_name = "Windows.VulnDriver.Cyvrlpc"
        reference_sample = "05f8f514d1367aca856564af5443a75f47d22a30ce63f0b024a41e6b9553a527"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] E9 95 BF E6 B2 99 E6 81 92 E7 A5 A5 E4 BF A1 E6 81 AF E6 8A 80 E6 9C AF E6 9C 89 E9 99 90 E5 85 AC E5 8F B8 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 63 00 79 00 76 00 72 00 6C 00 70 00 63 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x07][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x01][\x00-\x00][\x08-\x08][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x08-\x08][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00]|[\x02-\x02][\x00-\x00][\x08-\x08][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\xc1]|[\x00-\x2b][\xc2-\xc2])[\x02-\x02][\x00-\x00]|[\x02-\x02][\x00-\x00][\x08-\x08][\x00-\x00][\x2c-\x2c][\xc2-\xc2][\x02-\x02][\x00-\x00])/
        $str1 = { 43 00 6F 00 72 00 74 00 65 00 78 00 20 00 58 00 44 00 52 00 22 21 20 00 41 00 64 00 76 00 61 00 6E 00 63 00 65 00 64 00 20 00 45 00 6E 00 64 00 70 00 6F 00 69 00 6E 00 74 00 20 00 50 00 72 00 6F 00 74 00 65 00 63 00 74 00 69 00 6F 00 6E 00 }
        $str2 = "Cortex XDR LPC Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

