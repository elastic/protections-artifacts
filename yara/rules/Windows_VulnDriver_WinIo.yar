rule Windows_VulnDriver_WinIo_c9cc6d00 {
    meta:
        author = "Elastic Security"
        id = "c9cc6d00-b1ed-4bab-b0f7-4f0d6c03bf08"
        fingerprint = "d9050466a2894b63ae86ec8888046efb49053edcc20287b9f17a4e6340a9cf92"
        creation_date = "2022-04-04"
        last_modified = "2022-04-04"
        threat_name = "Windows.VulnDriver.WinIo"
        reference_sample = "e1980c6592e6d2d92c1a65acad8f1071b6a404097bb6fcce494f3c8ac31385cf"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "\\WinioSys.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

rule Windows_VulnDriver_WinIo_b0f21a70 {
    meta:
        author = "Elastic Security"
        id = "b0f21a70-b563-4b18-8ef9-73885125e88b"
        fingerprint = "00d8142a30e9815f8e4c53443221fc1c3882c8b6f68e77a8ed7ffe4fc8852488"
        creation_date = "2022-04-04"
        last_modified = "2022-04-04"
        threat_name = "Windows.VulnDriver.WinIo"
        reference_sample = "9fc29480407e5179aa8ea41682409b4ea33f1a42026277613d6484e5419de374"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "IOCTL_WINIO_WRITEMSR"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

rule Windows_VulnDriver_WinIo_6ab5231b {
    meta:
        author = "Elastic Security"
        id = "6ab5231b-14f8-48e6-9040-803b45611e7b"
        fingerprint = "e85a611c721e787e6f1adce4f2a7c8d4c24b516de210c7d60be3389edd01eef8"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: 上海弘玑信息技术有限公司"
        threat_name = "Windows.VulnDriver.WinIo"
        reference_sample = "385660a65e69b3bf9ac5c2ae4cadbb1e07f366e1807979bf7a915e40e9480f8b"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] E4 B8 8A E6 B5 B7 E5 BC 98 E7 8E 91 E4 BF A1 E6 81 AF E6 8A 80 E6 9C AF E6 9C 89 E9 99 90 E5 85 AC E5 8F B8 }
        $str1 = "WinIo.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

rule Windows_VulnDriver_WinIo_fa787472 {
    meta:
        author = "Elastic Security"
        id = "fa787472-7597-400e-a8f3-39d38dea62c7"
        fingerprint = "cccb26abc4a03928a6d7fbc50cb9a78c1c191c1bc5f610449b0f122598587241"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Gordion AB, Version: <= 1.1.1.0"
        threat_name = "Windows.VulnDriver.WinIo"
        reference_sample = "0bfcf39a3e63bb6ef8afec67965103df1b9803bca31d221a7fd4233972be9e05"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 47 6F 72 64 69 6F 6E 20 41 42 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 77 00 69 00 6E 00 69 00 6F 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00]|[\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00])/
        $str1 = "winio.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1
}

rule Windows_VulnDriver_WinIo_2d07d23d {
    meta:
        author = "Elastic Security"
        id = "2d07d23d-d913-4a47-90c5-169042f1833b"
        fingerprint = "1f38283f4414437f005db4c77239428065ee2690054183d998410412cec9f508"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: First International Computer, Inc., Version: <= 2.5.0.0"
        threat_name = "Windows.VulnDriver.WinIo"
        reference_sample = "8d5466ccce64de5beccc373e0c878ca3e624ed78d359f76aae32de4df5afce18"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 46 69 72 73 74 20 49 6E 74 65 72 6E 61 74 69 6F 6E 61 6C 20 43 6F 6D 70 75 74 65 72 2C 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 57 00 69 00 6E 00 49 00 6F 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x04][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x05-\x05][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "WinIo.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1
}

rule Windows_VulnDriver_WinIo_f9f7fa4d {
    meta:
        author = "Elastic Security"
        id = "f9f7fa4d-c377-4be6-9583-f74afc43d6a0"
        fingerprint = "52339c5477efa8c80465213bed5a3f9d84b9c7652240fa6fa48a51e38e3b442f"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Fuzhou TianxiaChuangshi Digital Co.,Ltd., Version: <= 7.2.1.6661"
        threat_name = "Windows.VulnDriver.WinIo"
        reference_sample = "9ef6eb93e504351d710b88fd5ec68ef2e0b757ea364341e715b0076dc559b54a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 46 75 7A 68 6F 75 20 54 69 61 6E 78 69 61 43 68 75 61 6E 67 73 68 69 20 44 69 67 69 74 61 6C 20 43 6F 2E 2C 4C 74 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 77 00 69 00 6E 00 69 00 6F 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x01][\x00-\x00][\x07-\x07][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x07-\x07][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00]|[\x02-\x02][\x00-\x00][\x07-\x07][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x19]|[\x00-\x04][\x1a-\x1a])[\x01-\x01][\x00-\x00]|[\x02-\x02][\x00-\x00][\x07-\x07][\x00-\x00][\x05-\x05][\x1a-\x1a][\x01-\x01][\x00-\x00])/
        $str1 = "QMacro's driver simulator module." wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1
}

rule Windows_VulnDriver_WinIo_7f97fe77 {
    meta:
        author = "Elastic Security"
        id = "7f97fe77-e25d-46cc-8ce8-689080d802b3"
        fingerprint = "93acfbb7d61efab2b77e71820158cd60cc3fae8dc3504f87aacdf4f3f9f7803a"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: ITE Tech. Inc., Version: <= 6.0.6000.16386"
        threat_name = "Windows.VulnDriver.WinIo"
        reference_sample = "f4acfebd83a351029dd812a0e40b44f5362f31ae80b6ae0b2fa2241687d34912"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 54 45 20 54 65 63 68 2E 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 77 00 69 00 6E 00 69 00 6F 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x16]|[\x00-\x6f][\x17-\x17])|[\x00-\x00][\x00-\x00][\x06-\x06][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x3f]|[\x00-\x01][\x40-\x40])[\x70-\x70][\x17-\x17]|[\x00-\x00][\x00-\x00][\x06-\x06][\x00-\x00][\x02-\x02][\x40-\x40][\x70-\x70][\x17-\x17])/
        $str1 = "WinIo.pdb"
        $str2 = "IOCTL_WRITE_PORT_UCHAR"
        $str3 = "IOCTL_READ_PORT_UCHAR"
        $str4 = "WINIOx64 Driver Version 1.1 " wide
        $str5 = "winio.sys x64 Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4 and $str5
}

