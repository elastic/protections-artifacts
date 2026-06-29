rule Windows_Ransomware_NightSpire_7b19fa09 {
    meta:
        author = "Elastic Security"
        id = "7b19fa09-6494-4b59-a808-a01a704c6734"
        fingerprint = "79637bd83bdcc52573b26b40e4f8317260a3d7991c13bbb65a5ff16265c73c9f"
        creation_date = "2026-06-09"
        last_modified = "2026-06-26"
        threat_name = "Windows.Ransomware.NightSpire"
        reference_sample = "69f5515ff3f554233840ad2f2397b345f955013017a9ae14ed4e762f52d936af"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = "by NightSpire.Team" fullword
        $b = ">>> Using qTox Chat App" fullword
        $c = "/[NSPIRE_MSG].txt"
        $d = "Answer.nspire"
        $e = "change the icon of nspire file" fullword
        $f = "main.MakeReadMeFile" fullword
        $g = "main.writeToTail" fullword
        $h = "main.checkPossibility" fullword
        $i = "nightspireteam" fullword
        $j = "Specify the Encryption Method."
    condition:
        4 of them
}

