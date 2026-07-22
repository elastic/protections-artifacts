rule Windows_VulnDriver_IFlytek_571597c5 {
    meta:
        author = "Elastic Security"
        id = "571597c5-ccb6-44d7-b299-5f1c52db60f7"
        fingerprint = "cdf930cda208252afeffa99fc6ae76277855c79b7d1fa2923fcb607a4b30a226"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: iFLYTEK Co.,Ltd., Version: <= 1.0.0.1"
        threat_name = "Windows.VulnDriver.IFlytek"
        reference_sample = "e1d11927370965dbd769f9270876a3b6839631d9b523c7a26d9de7761279f008"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 69 46 4C 59 54 45 4B 20 43 6F 2E 2C 4C 74 64 2E }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "iFlyWinRing0x64.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1
}

