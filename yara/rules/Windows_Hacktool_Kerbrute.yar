rule Windows_Hacktool_Kerbrute_f73e1182 {
    meta:
        author = "Elastic Security"
        id = "f73e1182-24d8-459a-b843-d91987587e8c"
        fingerprint = "2279b5accd20b06fce70b87a39576fc2ebbac74934a5846155295ae0be18b9cd"
        creation_date = "2026-09-21"
        last_modified = "2026-09-28"
        threat_name = "Windows.Hacktool.Kerbrute"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $sym_session = "github.com/ropnop/kerbrute/session.KerbruteSession.TestUsername" ascii fullword
        $sym_worker = "github.com/ropnop/kerbrute/cmd.makeSprayWorker" ascii fullword
        $sym_enum_worker = "github.com/ropnop/kerbrute/cmd.makeEnumWorker" ascii fullword
        $bruteforce_str = "bruteForceCombos"
        $msg_user = "[+] VALID USERNAME:\t %s"
        $msg_enum = "userenum [flags] <username_wordlist>"
    condition:
        3 of them
}

