rule Windows_Hacktool_Generic_033965e7 {
    meta:
        author = "Elastic Security"
        id = "033965e7-8c71-4a95-bd6c-c68b730d6cd3"
        fingerprint = "8bff946c35f5d325245313614a1e7911ccba69777316d97487cdc2da0e349e07"
        creation_date = "2026-09-21"
        last_modified = "2026-09-28"
        threat_name = "Windows.Hacktool.Generic"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $s_trampoline = "[DEBUG]Calling WriteProcessMemory to overwrite AddressofEntryPoint at 0x%x with trampoline: 0x%x..."
        $s_overwrite = "[-]Successfully overwrote the AddressofEntryPoint"
        $s_machine = "[-]Machine type UNKOWN: 0x%x"
        $s_resume = "[+]Process resumed and shellcode executed"
        $s_header = "[-]ReadProcessMemory completed reading %d bytes for IMAGE_OPTIONAL_HEADER"
    condition:
        4 of them
}

rule Windows_Hacktool_Generic_922943d8 {
    meta:
        author = "Elastic Security"
        id = "922943d8-9008-4a3d-9b56-4892636140ec"
        fingerprint = "c606a76ae0b427bea0eec8e457593a7a694d795773f1af23481ccbfa54b6de82"
        creation_date = "2026-09-21"
        last_modified = "2026-09-28"
        threat_name = "Windows.Hacktool.Generic"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $s_registry = "[+] Looking for the 'Registry Editor' window..." ascii fullword
        $s_listview = "[+] Looking for the 'SysListView32' window..." ascii fullword
        $s_terminate = "[+] RegEdit process termination successfull." ascii fullword
        $s_empty = "[-] List view is empty." ascii fullword
        $s_alloc = "[+] Allocating memory in the remote process..." ascii fullword
        $s_post = "[+] Posting message to the target window..." ascii fullword
    condition:
        4 of them
}

rule Windows_Hacktool_Generic_42e0be24 {
    meta:
        author = "Elastic Security"
        id = "42e0be24-b631-4d1a-97d5-a9cee97fbbb3"
        fingerprint = "59220437136460f030274537d69889928260d9fc7055d1aec14c1795b05a8234"
        creation_date = "2026-09-21"
        last_modified = "2026-09-28"
        threat_name = "Windows.Hacktool.Generic"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $s_load = "[DEBUG]Loading VirtualAlloc, VirtualProtect and RtlCopyMemory procedures"
        $s_copy = "[DEBUG]Copying shellcode to memory with RtlCopyMemory"
        $s_protect = "[DEBUG]Calling VirtualProtect to change memory region to PAGE_EXECUTE_READ"
        $s_decode = "[!]there was an error decoding the string to a hex byte array: %s"
        $s_done = "[-]Shellcode memory region changed to PAGE_EXECUTE_READ"
    condition:
        4 of them
}

rule Windows_Hacktool_Generic_bafe5bc4 {
    meta:
        author = "Elastic Security"
        id = "bafe5bc4-2216-4319-908b-09373585754f"
        fingerprint = "55df1ab3fc49b5a674c5b1fdc8b7612b38dcc10ffd01acab4f8245c4131f60d7"
        creation_date = "2026-09-21"
        last_modified = "2026-09-28"
        threat_name = "Windows.Hacktool.Generic"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $seq_1 = { 83 65 FC 00 6A 00 68 80 00 00 00 6A 03 6A 00 6A 01 68 00 00 00 80 FF 75 08 FF 15 08 60 41 00 }
        $usage = "[ usage: xbin <exe> <section name>" ascii fullword
        $msg_object = "[ Looks like an object file" ascii fullword
        $msg_raw = "%8X file pointer to raw data (%08X to %08X)" ascii fullword
        $msg_nt = "  [ invalid nt header" ascii fullword
    condition:
        4 of them
}

rule Windows_Hacktool_Generic_27dce09e {
    meta:
        author = "Elastic Security"
        id = "27dce09e-c774-4bbd-9b5c-88e6a6bcc668"
        fingerprint = "9c74c3db517b9aa6482fa7e97114ae69e3107db7f10cd6a38856915fd12dfb60"
        creation_date = "2026-09-21"
        last_modified = "2026-09-28"
        threat_name = "Windows.Hacktool.Generic"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $seq_1 = { 55 89 E5 83 EC 18 C7 44 24 04 01 00 00 00 C7 04 24 00 40 F8 61 A1 0C 71 F8 61 FF D0 83 EC 08 90 C9 }
        $str_1 = "beerTime"
    condition:
        all of them
}

rule Windows_Hacktool_Generic_5161f303 {
    meta:
        author = "Elastic Security"
        id = "5161f303-7e6c-44d7-8250-a37dc8bf5b91"
        fingerprint = "c8bc6dbff7f8fd1a97f3a55309a3f53df86691d0eda82f290dc09e4734b50481"
        creation_date = "2026-09-21"
        last_modified = "2026-09-28"
        threat_name = "Windows.Hacktool.Generic"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str_1 = "Hello From Main...I Don't Do Anything" wide fullword
        $str_2 = "Hello There From Uninstall" wide fullword
        $str_3 = "I shouldn't really execute either." wide fullword
        $str_4 = "Allthingsdll_64.dll" fullword
    condition:
        3 of them
}

rule Windows_Hacktool_Generic_45b88d7a {
    meta:
        author = "Elastic Security"
        id = "45b88d7a-1eb3-41a8-821b-378fe745aa9d"
        fingerprint = "7ee9fa5ea1f7a33ec44076ba0cc3fb9fae8fc7bb67e12af92ae3f325f63bfed9"
        creation_date = "2026-09-21"
        last_modified = "2026-09-28"
        threat_name = "Windows.Hacktool.Generic"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str_1 = "C:\\src\\x64\\Release\\AltWinSock2DLL.pdb" wide fullword
        $seq_1 = { 48 8D 05 B7 61 01 00 48 8B D7 48 89 44 24 28 4C 8D 8D 70 01 00 00 48 8D 45 60 4C 8D 05 B1 61 01 00 48 89 44 24 20 48 8D 4C 24 50 E8 2E 01 00 00 }
        $seq_2 = { 00 28 06 00 00 06 26 12 00 1D 28 0E 00 00 0A 1F F5 28 04 00 00 06 0B 72 01 00 00 70 28 0F 00 00 0A 00 28 10 00 00 0A 0C 00 08 28 02 00 00 06 28 11 00 00 0A 00 00 DE 11 }
        $seq_3 = { 48 89 54 24 10 48 89 4C 24 08 48 81 EC F8 00 00 00 48 C7 44 24 28 00 00 00 00 C7 44 24 20 00 00 00 00 45 33 C9 4C 8D 05 74 01 00 00 33 D2 33 C9 FF 15 0A DF 00 00 C7 44 24 30 B8 00 00 00 48 C7 44 24 38 00 00 00 00 48 8D 05 E2 01 00 00 48 89 44 24 40 48 8D 05 F6 01 00 00 48 89 44 24 48 48 8D 05 0A 02 00 00 48 89 44 24 50 48 8D 05 CE FE FF FF 48 89 44 24 58 48 8D 05 E2 FE FF FF 48 89 44 24 60 48 8D 05 06 02 00 00 48 89 44 24 68 48 8D 05 EA FE FF FF 48 89 44 24 70 48 C7 44 24 78 00 00 00 00 48 C7 84 24 80 00 00 00 00 00 00 00 48 C7 84 24 88 00 00 00 00 00 00 00 48 C7 84 24 90 00 00 00 00 00 00 00 48 C7 84 24 98 00 00 00 00 00 00 00 48 C7 84 24 A0 00 00 00 00 00 00 00 48 8D 05 B9 FE FF FF 48 89 84 24 A8 00 00 00 48 8D 05 CA FE FF FF 48 89 84 24 B0 00 00 00 48 8D 05 DB FE FF FF 48 89 84 24 B8 00 00 00 48 8D 05 9C 01 00 00 48 89 84 24 C0 00 00 00 48 C7 84 24 C8 00 00 00 00 00 00 00 48 8D 05 91 01 00 00 48 89 84 24 D0 00 00 00 48 8D 05 A2 01 00 00 48 89 84 24 D8 00 00 00 48 8D 05 B3 01 00 00 48 89 84 24 E0 00 00 00 48 8D 44 24 30 48 81 C4 F8 00 00 00 C3 }
    condition:
        1 of them
}

rule Windows_Hacktool_Generic_bb05d541 {
    meta:
        author = "Elastic Security"
        id = "bb05d541-def6-4921-b3d5-81b1c57a7af0"
        fingerprint = "ad8f9fe64183880bf471aa162b830c3916417b22eb4fbe572e0b6c85226799e9"
        creation_date = "2026-09-21"
        last_modified = "2026-09-28"
        threat_name = "Windows.Hacktool.Generic"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str_1 = "wextract.pdb" wide fullword
        $str_3 = { 4C 8D 05 11 73 00 00 C7 44 24 34 04 01 00 00 48 8D 44 24 40 BA 04 01 00 00 4C 2B C0 48 8D 4C 24 40 }
        $seq_2 = { 48 8D 44 24 38 41 B9 19 00 02 00 45 33 C0 48 89 44 24 20 48 8D 15 47 22 00 00 }
    condition:
        all of them
}

