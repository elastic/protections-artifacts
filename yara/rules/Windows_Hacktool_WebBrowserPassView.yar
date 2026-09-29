rule Windows_Hacktool_WebBrowserPassView_ddbe01d9 {
    meta:
        author = "Elastic Security"
        id = "ddbe01d9-4f1f-4ff4-b71c-654b40e3c37f"
        fingerprint = "dbc41fc8098c372002970a6ff937b199917729c0e41510affd7e56cd6177cd10"
        creation_date = "2026-09-21"
        last_modified = "2026-09-28"
        threat_name = "Windows.Hacktool.WebBrowserPassView"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $s_title = "Web Browser Password Viewer" wide fullword
        $s_chrome = "Choose another profile of Chrome Web browser" wide fullword
        $s_opera = "Choose the password file of Opera (wand.dat)" wide fullword
        $s_load = "Load Passwords From..." wide fullword
        $s_passwords = "%d Passwords" wide fullword
    condition:
        3 of them
}

