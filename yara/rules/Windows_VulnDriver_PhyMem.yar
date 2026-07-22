rule Windows_VulnDriver_PhyMem_015d8d1d {
    meta:
        author = "Elastic Security"
        id = "015d8d1d-f7c5-4758-bb8a-7a4fbb3bd191"
        fingerprint = "d7434374a2c3fd8f9716a35b177476dc4d9a9ecc10e44bd260b2222ba1caee9f"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Super Micro Computer, Inc., Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.PhyMem"
        reference_sample = "1963d5a0e512b72353953aadbe694f73a9a576f0241a988378fa40bf574eda52"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 75 70 65 72 20 4D 69 63 72 6F 20 43 6F 6D 70 75 74 65 72 2C 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 70 00 68 00 79 00 6D 00 65 00 6D 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "phymem Application" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1
}

