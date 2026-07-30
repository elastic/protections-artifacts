rule Windows_VulnDriver_EnCase_4387da30 {
    meta:
        author = "Elastic Security"
        id = "4387da30-0ad8-448f-9989-23df2b354307"
        fingerprint = "41889615b74418ff41b28d05084809af7d9fb3bade6959fde0459924b0c5678a"
        creation_date = "2026-02-09"
        last_modified = "2026-07-29"
        description = "Subject: Guidance Software Inc., Name: EnPortv.sys, Version: 1.56.0.0, Product Name: EnCase Driver"
        threat_name = "Windows.VulnDriver.EnCase"
        reference_sample = "3111f4d7d4fac55103453c4c8adb742def007b96b7c8ed265347df97137fbee0"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 47 75 69 64 61 6E 63 65 20 53 6F 66 74 77 61 72 65 2C 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 [1-8] 45 00 6E 00 50 00 6F 00 72 00 74 00 76 00 2E 00 73 00 79 00 73 00 }
        $file_version_number = { 46 00 69 00 6C 00 65 00 56 00 65 00 72 00 73 00 69 00 6F 00 6E [1-8] 20 00 20 00 20 00 20 00 00 00 00 00 38 00 0C 00 01 00 }
        $product_name = { 50 00 72 00 6F 00 64 00 75 00 63 00 74 00 4E 00 61 00 6D 00 65 [1-8] 45 00 6E 00 43 00 61 00 73 00 65 00 20 00 44 00 72 00 69 00 76 00 65 00 72 00 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $file_version_number and $product_name
}

