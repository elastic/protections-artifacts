rule Windows_VulnDriver_XTier_48bb4b2c {
    meta:
        author = "Elastic Security"
        id = "48bb4b2c-da6c-4e2a-bbbe-75c7a892bdc6"
        fingerprint = "5868b9027e8f111825c79bd64b3a99a57a0cefe981e45762c7aaec7a4aacaf62"
        creation_date = "2022-04-07"
        last_modified = "2022-04-07"
        description = "Name: nscm.sys, Version: 3.1.12.0"
        threat_name = "Windows.VulnDriver.XTier"
        reference_sample = "0f726d8ce21c0c9e01ebe6b55913c519ad6086bcaec1a89f8308f3effacd435f"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6E 00 73 00 63 00 6D 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x01][\x00-\x00])([\x00-\x03][\x00-\x00])([\x00-\x00][\x00-\x00])([\x00-\x0c][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x02][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x00][\x00-\x00])([\x00-\x03][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x01][\x00-\x00])([\x00-\x03][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\x0b][\x00-\x00]))/
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name in (filesize - 50KB .. filesize) and $version in (filesize - 50KB .. filesize)
}

rule Windows_VulnDriver_XTier_8a2f6dc1 {
    meta:
        author = "Elastic Security"
        id = "8a2f6dc1-82f4-4e87-a4d6-49a36ea4fab8"
        fingerprint = "ecd5fe7fde353bf73382fb35850522ac956b91a1bcb015f35f5eaee9fa937b70"
        creation_date = "2022-04-07"
        last_modified = "2022-04-07"
        description = "Name: libnicm.sys, Version: 3.1.12.0"
        threat_name = "Windows.VulnDriver.XTier"
        reference_sample = "95d50c69cdbf10c9c9d61e64fe864ac91e6f6caa637d128eb20e1d3510e776d3"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6C 00 69 00 62 00 6E 00 69 00 63 00 6D 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x01][\x00-\x00])([\x00-\x03][\x00-\x00])([\x00-\x00][\x00-\x00])([\x00-\x0c][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x02][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x00][\x00-\x00])([\x00-\x03][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x01][\x00-\x00])([\x00-\x03][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\x0b][\x00-\x00]))/
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name in (filesize - 50KB .. filesize) and $version in (filesize - 50KB .. filesize)
}

rule Windows_VulnDriver_XTier_f4760d4a {
    meta:
        author = "Elastic Security"
        id = "f4760d4a-42da-4bb8-87ff-3b2e709c6a95"
        fingerprint = "b7bae9be1e3235ab917843ae4d34980dd74b48bcd2965334f5f09b3c8d184484"
        creation_date = "2022-04-07"
        last_modified = "2022-04-07"
        description = "Name: NICM.SYS, Version: 3.1.12.0"
        threat_name = "Windows.VulnDriver.XTier"
        reference_sample = "0e14a4401011a9f4e444028ac5b1595da34bbbf9af04a00670f15ff839734003"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4E 00 49 00 43 00 4D 00 2E 00 53 00 59 00 53 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x01][\x00-\x00])([\x00-\x03][\x00-\x00])([\x00-\x00][\x00-\x00])([\x00-\x0c][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x02][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x00][\x00-\x00])([\x00-\x03][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x01][\x00-\x00])([\x00-\x03][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\x0b][\x00-\x00]))/
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name in (filesize - 50KB .. filesize) and $version in (filesize - 50KB .. filesize)
}

rule Windows_VulnDriver_XTier_6a7de49f {
    meta:
        author = "Elastic Security"
        id = "6a7de49f-1a31-4ce0-b4b1-cdc670bfdf18"
        fingerprint = "1f306284caedae4894057829fd3db0b17546ed59d7c829f8ccda755a95552214"
        creation_date = "2022-04-07"
        last_modified = "2022-04-07"
        description = "Name: NCPL.SYS, Version: 3.1.12.0"
        threat_name = "Windows.VulnDriver.XTier"
        reference_sample = "26c86227d3f387897c1efd77dc711eef748eb90be84149cb306e3d4c45cc71c7"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4E 00 43 00 50 00 4C 00 2E 00 53 00 59 00 53 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x01][\x00-\x00])([\x00-\x03][\x00-\x00])([\x00-\x00][\x00-\x00])([\x00-\x0c][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x02][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x00][\x00-\x00])([\x00-\x03][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x01][\x00-\x00])([\x00-\x03][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\x0b][\x00-\x00]))/
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name in (filesize - 50KB .. filesize) and $version in (filesize - 50KB .. filesize)
}

