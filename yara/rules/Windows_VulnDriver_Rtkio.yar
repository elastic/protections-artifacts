rule Windows_VulnDriver_Rtkio_13b3c88b {
    meta:
        author = "Elastic Security"
        id = "13b3c88b-daa7-4402-ad31-6fc7d4064087"
        fingerprint = "ff671f98f85bbae3fefda7f2f1769035e240765ed8919909e22029e48c45a02b"
        creation_date = "2022-04-07"
        last_modified = "2022-04-07"
        description = "Name: rtkio.sys"
        threat_name = "Windows.VulnDriver.Rtkio"
        reference_sample = "478917514be37b32d5ccf76e4009f6f952f39f5553953544f1b0688befd95e82"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 72 00 74 00 6B 00 69 00 6F 00 2E 00 73 00 79 00 73 00 00 00 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name in (filesize - 50KB .. filesize)
}

rule Windows_VulnDriver_Rtkio_d595781e {
    meta:
        author = "Elastic Security"
        id = "d595781e-67c1-47bf-a7ea-bb4a9ba33879"
        fingerprint = "c19dcdf92718381aa418114ba24a8b3dc8eadb2485edf58d272be2e3a9b7c1f4"
        creation_date = "2022-04-07"
        last_modified = "2022-04-07"
        description = "Name: rtkio64.sys"
        threat_name = "Windows.VulnDriver.Rtkio"
        reference_sample = "4ed2d2c1b00e87b926fb58b4ea43d2db35e5912975f4400aa7bd9f8c239d08b7"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 72 00 74 00 6B 00 69 00 6F 00 36 00 34 00 2E 00 73 00 79 00 73 00 20 00 00 00 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name in (filesize - 50KB .. filesize)
}

rule Windows_VulnDriver_Rtkio_b09af431 {
    meta:
        author = "Elastic Security"
        id = "b09af431-307b-40e2-bac5-5865c1ad54c8"
        fingerprint = "140edf2cfd37c449f1348d0af4a9fc19da6b4e4ee0e20134884fdf1759fe5f00"
        creation_date = "2022-04-07"
        last_modified = "2022-04-07"
        description = "Name: rtkiow8x64.sys"
        threat_name = "Windows.VulnDriver.Rtkio"
        reference_sample = "b205835b818d8a50903cf76936fcf8160060762725bd74a523320cfbd091c038"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 72 00 74 00 6B 00 69 00 6F 00 77 00 38 00 78 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name in (filesize - 50KB .. filesize)
}

rule Windows_VulnDriver_Rtkio_5693e967 {
    meta:
        author = "Elastic Security"
        id = "5693e967-dbe4-457c-8b0c-404774871ac0"
        fingerprint = "72d179998b70afae81d8255d97cbad70efabb6cab779bf8979f98e43b9352932"
        creation_date = "2022-04-07"
        last_modified = "2022-04-07"
        description = "Name: rtkiow10x64.sys"
        threat_name = "Windows.VulnDriver.Rtkio"
        reference_sample = "ab8f2217e59319b88080e052782e559a706fa4fb7b8b708f709ff3617124da89"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 72 00 74 00 6B 00 69 00 6F 00 77 00 31 00 30 00 78 00 36 00 34 00 2E 00 73 00 79 00 73 00 20 00 00 00 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name in (filesize - 50KB .. filesize)
}

