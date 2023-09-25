rule Multi_Trojan_Mythic_4beb7e17 {
    meta:
        author = "Elastic Security"
        id = "4beb7e17-34c2-4f5c-a668-e54512175f53"
        fingerprint = "0b25c5b069cec31e9af31b7822ea19b813fe1882dfaa584661ff14414ae41df5"
        creation_date = "2023-08-01"
        last_modified = "2023-09-20"
        threat_name = "Multi.Trojan.Mythic"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $a1 = "task_id"
        $a2 = "post_response"
        $a3 = "c2_profile"
        $a4 = "get_tasking"
        $a5 = "tasking_size"
        $a6 = "get_delegate_tasks"
        $a7 = "total_chunks"
        $a8 = "is_screenshot"
        $a9 = "file_browser"
        $a10 = "is_file"
        $a11 = "access_time"
    condition:
        7 of them
}

