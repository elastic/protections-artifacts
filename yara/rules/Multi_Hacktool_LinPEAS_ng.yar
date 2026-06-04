rule Multi_Hacktool_LinPEAS_ng_19e3957f {
    meta:
        author = "Elastic Security"
        id = "19e3957f-8f44-47e1-abf8-a40de645594e"
        fingerprint = "c2e952348ce89a802cedcb089bb1306d3f8f077262753133a35b7a18f8711ba8"
        creation_date = "2022-12-21"
        last_modified = "2026-05-22"
        description = "LinPEAS detection based on the systen information module"
        threat_name = "Multi.Hacktool.LinPEAS-ng"
        reference_sample = "593333df3a1e109c73e8823e3929d52a7fc79a3064eb62004f33f11daca10d0b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $cve_0 = "CVEs Check" base64
        $cve_1 = "Vulnerable to CVE-2021-4034" base64
        $cve_2 = "Vulnerable to CVE-2021-3560" base64
        $cve_3 = "Potentially Vulnerable to CVE-2022-0847" base64
        $cve_4 = "Potentially Vulnerable to CVE-2022-2588" base64
        $cpu_0 = "Any sd*/disk* disk in /dev?" base64
        $cpu_1 = "$(command -v diskutil)" base64
        $cpu_2 = "Mounted disks information" base64
        $cpu_3 = "$(command -v smbutil)" base64
        $protections_0 = "grsecurity present?" base64
        $protections_1 = "AppArmor enabled?" base64
        $protections_2 = "User namespace?" base64
        $protections_3 = "XProtectPlistConfigData" base64
    condition:
        (2 of ($cve_*) and 2 of ($cpu_*) and 2 of ($protections_*))
}

rule Multi_Hacktool_LinPEAS_ng_f3ab706d {
    meta:
        author = "Elastic Security"
        id = "f3ab706d-1ad4-4ff2-a461-f877c7990dbb"
        fingerprint = "a41a8ff83d1c94b63fb1ecbeded1e54b7d93fb4698ed8dda01b122d1f328de36"
        creation_date = "2022-12-21"
        last_modified = "2026-05-22"
        description = "LinPEAS detection based on the systen information module"
        threat_name = "Multi.Hacktool.LinPEAS-ng"
        reference_sample = "cc3e69418622499a21248c762373642eb2a2b1073767f22f0dd0f65d0def94a5"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $cve_0 = "CVEs Check"
        $cve_1 = "Vulnerable to CVE-2021-4034"
        $cve_2 = "Vulnerable to CVE-2021-3560"
        $cve_3 = "Potentially Vulnerable to CVE-2022-0847"
        $cve_4 = "Potentially Vulnerable to CVE-2022-2588"
        $cpu_0 = "Any sd*/disk* disk in /dev?"
        $cpu_1 = "$(command -v diskutil)"
        $cpu_2 = "Mounted disks information"
        $cpu_3 = "$(command -v smbutil)"
        $protections_0 = "grsecurity present?"
        $protections_1 = "AppArmor enabled?"
        $protections_2 = "User namespace?"
        $protections_3 = "XProtectPlistConfigData"
    condition:
        (2 of ($cve_*) and 2 of ($cpu_*) and 2 of ($protections_*))
}

rule Multi_Hacktool_LinPEAS_ng_25b07260 {
    meta:
        author = "Elastic Security"
        id = "25b07260-68ab-4b69-a6bb-a4056014329b"
        fingerprint = "0ec6241c4dba1e806c654056257fce7ddd67a4b2cd36d3e19a2c486b5befb7aa"
        creation_date = "2022-12-21"
        last_modified = "2026-05-22"
        description = "LinPEAS detection based on the container module"
        threat_name = "Multi.Hacktool.LinPEAS-ng"
        reference_sample = "593333df3a1e109c73e8823e3929d52a7fc79a3064eb62004f33f11daca10d0b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $container_0 = "find / -maxdepth 3 -name '*dockerenv*'" base64
        $container_1 = "/kubepod" base64
        $container_2 = "container=podman" base64
        $container_3 = "$(grep -a 'container=' /proc/1/environ" base64
        $container_4 = "You have write permissions over interesting socket" base64
        $container_5 = "Am I Containered?" base64
        $container_6 = "release_agent breakout" base64
        $container_7 = "DoS via panic_" base64
        $container_8 = "Container Capabilities" base64
        $container_9 = "$(command -v capsh)" base64
    condition:
        5 of them
}

rule Multi_Hacktool_LinPEAS_ng_fd5b32cf {
    meta:
        author = "Elastic Security"
        id = "fd5b32cf-b96c-41a1-8119-5a688a1e2ebf"
        fingerprint = "d19f8c7ed050f6c45e613aa70aa5ddd1dc0b7a7d1309d31bc2b5eb969fff6868"
        creation_date = "2022-12-21"
        last_modified = "2026-05-22"
        description = "LinPEAS detection based on the container module"
        threat_name = "Multi.Hacktool.LinPEAS-ng"
        reference_sample = "cc3e69418622499a21248c762373642eb2a2b1073767f22f0dd0f65d0def94a5"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $container_0 = "find / -maxdepth 3 -name '*dockerenv*'"
        $container_1 = "/kubepod"
        $container_2 = "container=podman"
        $container_3 = "$(grep -a 'container=' /proc/1/environ"
        $container_4 = "You have write permissions over interesting socket"
        $container_5 = "Am I Containered?"
        $container_6 = "release_agent breakout"
        $container_7 = "DoS via panic_"
        $container_8 = "Container Capabilities"
        $container_9 = "$(command -v capsh)"
    condition:
        5 of them
}

rule Multi_Hacktool_LinPEAS_ng_d233c491 {
    meta:
        author = "Elastic Security"
        id = "d233c491-d506-49d4-958d-a13ef77fcc71"
        fingerprint = "b6a805f34fb1b7847c1d1180f8c43742aadfa4f9667ad590d3266b69cfde7419"
        creation_date = "2022-12-21"
        last_modified = "2026-05-22"
        description = "LinPEAS detection based on the cloud module"
        threat_name = "Multi.Hacktool.LinPEAS-ng"
        reference_sample = "cc3e69418622499a21248c762373642eb2a2b1073767f22f0dd0f65d0def94a5"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $cloud_0 = "/devstorage.read_only|/logging.write"
        $cloud_1 = "/monitoring|/servicecontrol|/service.management.readonly"
        $cloud_2 = "grep -q metadata.google.internal /etc/hosts"
        $cloud_3 = "Google Cloud Platform?"
        $cloud_4 = "AWS ECS?"
        $cloud_5 = "Project-ID:"
        $cloud_6 = "OSLogin users:"
        $cloud_7 = "Instance Image:"
        $cloud_8 = "X-aws-ec2-metadata-token:"
        $cloud_9 = "AWS Lambda Enumeration"
    condition:
        5 of them
}

rule Multi_Hacktool_LinPEAS_ng_1eb10406 {
    meta:
        author = "Elastic Security"
        id = "1eb10406-aed8-4411-9b6a-5e9cada72c29"
        fingerprint = "d48658714fdab4127535a91ee883e9d0443ed46b6d4c9ff88543cb9f5e940462"
        creation_date = "2022-12-21"
        last_modified = "2026-05-22"
        description = "LinPEAS detection based on the cloud module"
        threat_name = "Multi.Hacktool.LinPEAS-ng"
        reference_sample = "593333df3a1e109c73e8823e3929d52a7fc79a3064eb62004f33f11daca10d0b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $cloud_0 = "/devstorage.read_only|/logging.write" base64
        $cloud_1 = "/monitoring|/servicecontrol|/service.management.readonly" base64
        $cloud_2 = "grep -q metadata.google.internal /etc/hosts" base64
        $cloud_3 = "Google Cloud Platform?" base64
        $cloud_4 = "AWS ECS?" base64
        $cloud_5 = "Project-ID:" base64
        $cloud_6 = "OSLogin users:" base64
        $cloud_7 = "Instance Image:" base64
        $cloud_8 = "X-aws-ec2-metadata-token:" base64
        $cloud_9 = "AWS Lambda Enumeration" base64
    condition:
        5 of them
}

rule Multi_Hacktool_LinPEAS_ng_46488ab2 {
    meta:
        author = "Elastic Security"
        id = "46488ab2-093f-4371-b806-00e1df5c144e"
        fingerprint = "d12007aa8b6ad1dea30a46fb2b3d39b3a77ef18f6a2ecf6756a6a997e22ccb05"
        creation_date = "2022-12-21"
        last_modified = "2026-05-22"
        description = "LinPEAS detection based on the Processes & Cron & Services & Timers module"
        threat_name = "Multi.Hacktool.LinPEAS-ng"
        reference_sample = "cc3e69418622499a21248c762373642eb2a2b1073767f22f0dd0f65d0def94a5"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $cron_0 = "Looks like ps is not finding processes"
        $cron_1 = "(ps fauxwww || ps auxwww | sort ) 2>/dev/null | grep -v \"\\[\" | grep -v \"%CPU\""
        $cron_2 = "/dev/null | grep CapEff | awk"
        $cron_3 = "awk '!x[$0]++' 2>/dev/null | grep -v \" root root \""
        $cron_4 = "Files opened by processes belonging to other users"
        $cron_5 = "gdm-password process found (dump creds from memory as root)"
        $cron_6 = "-name \"cron*\" -or -name \"anacron\" -or -name \"anacrontab\""
        $cron_7 = "/Library/LaunchDaemons/MonitorHelper.plist ProgramArguments"
        $cron_8 = "SPStartupItemDataType"
        $cron_9 = "Unix Sockets Listening"
    condition:
        5 of them
}

rule Multi_Hacktool_LinPEAS_ng_709a480d {
    meta:
        author = "Elastic Security"
        id = "709a480d-f797-4ad0-a67b-6e4b814ffc18"
        fingerprint = "06af5a1d00998d44113c69b5bcf494bbda52ffc63b1013681d46d2122545cded"
        creation_date = "2022-12-21"
        last_modified = "2026-05-22"
        description = "LinPEAS detection based on the Processes & Cron & Services & Timers module"
        threat_name = "Multi.Hacktool.LinPEAS-ng"
        reference_sample = "593333df3a1e109c73e8823e3929d52a7fc79a3064eb62004f33f11daca10d0b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $cron_0 = "Looks like ps is not finding processes" base64
        $cron_1 = "(ps fauxwww || ps auxwww | sort ) 2>/dev/null | grep -v \"\\[\" | grep -v \"%CPU\"" base64
        $cron_2 = "/dev/null | grep CapEff | awk" base64
        $cron_3 = "awk '!x[$0]++' 2>/dev/null | grep -v \" root root \"" base64
        $cron_4 = "Files opened by processes belonging to other users" base64
        $cron_5 = "gdm-password process found (dump creds from memory as root)" base64
        $cron_6 = "-name \"cron*\" -or -name \"anacron\" -or -name \"anacrontab\"" base64
        $cron_7 = "/Library/LaunchDaemons/MonitorHelper.plist ProgramArguments" base64
        $cron_8 = "SPStartupItemDataType" base64
        $cron_9 = "Unix Sockets Listening" base64
    condition:
        5 of them
}

rule Multi_Hacktool_LinPEAS_ng_f9a55fb7 {
    meta:
        author = "Elastic Security"
        id = "f9a55fb7-e457-4b39-943d-a4f99d3a93bf"
        fingerprint = "ffbb559253e242fed1881027e59519a5debe1095237d6efcac5604dd4ac2d2c5"
        creation_date = "2022-12-22"
        last_modified = "2026-05-22"
        description = "LinPEAS detection based on the Network info module"
        threat_name = "Multi.Hacktool.LinPEAS-ng"
        reference_sample = "cc3e69418622499a21248c762373642eb2a2b1073767f22f0dd0f65d0def94a5"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $network_0 = "Hostname, hosts and DNS"
        $network_1 = "Networks and neighbours"
        $network_2 = "(route || ip n || cat /proc/net/route)"
        $network_3 = "networksetup -listallhardwareports"
        $network_4 = "timeout 1 tcpdump >/dev/null"
        $network_5 = "[-] No ifconfig or ip commands"
        $network_6 = "$(netstat -na | grep LISTEN | grep tcp46 | grep \"*.3283\" | wc -l);"
        $network_7 = "The following services are OFF if"
        $network_8 = "s,Password|Authorization Name.*"
        $network_9 = "host.docker.internal"
    condition:
        5 of them
}

rule Multi_Hacktool_LinPEAS_ng_4c86542f {
    meta:
        author = "Elastic Security"
        id = "4c86542f-ca54-4bdb-a91a-faee83a0e7ac"
        fingerprint = "b2d75cc3f187a00b85c092dc683e9efee6f116f02e1cbc5296402f42fd328436"
        creation_date = "2022-12-22"
        last_modified = "2026-05-22"
        description = "LinPEAS detection based on the Network info module"
        threat_name = "Multi.Hacktool.LinPEAS-ng"
        reference_sample = "593333df3a1e109c73e8823e3929d52a7fc79a3064eb62004f33f11daca10d0b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $network_0 = "Hostname, hosts and DNS" base64
        $network_1 = "Networks and neighbours" base64
        $network_2 = "(route || ip n || cat /proc/net/route)" base64
        $network_3 = "networksetup -listallhardwareports" base64
        $network_4 = "timeout 1 tcpdump >/dev/null" base64
        $network_5 = "[-] No ifconfig or ip commands" base64
        $network_6 = "$(netstat -na | grep LISTEN | grep tcp46 | grep \"*.3283\" | wc -l);" base64
        $network_7 = "The following services are OFF if" base64
        $network_8 = "s,Password|Authorization Name.*" base64
        $network_9 = "host.docker.internal" base64
    condition:
        5 of them
}

rule Multi_Hacktool_LinPEAS_ng_62eff03d {
    meta:
        author = "Elastic Security"
        id = "62eff03d-146c-411d-9ee4-418ef94e4003"
        fingerprint = "784fa26c75dbb9deecfacf2098147554706b1c40ab84aa625bc8c8df84fc7cf5"
        creation_date = "2022-12-22"
        last_modified = "2026-05-22"
        description = "LinPEAS detection based on the User info module"
        threat_name = "Multi.Hacktool.LinPEAS-ng"
        reference_sample = "cc3e69418622499a21248c762373642eb2a2b1073767f22f0dd0f65d0def94a5"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $user_0 = "Current user Login and Logout hooks"
        $user_1 = "/var/db/SystemKey"
        $user_2 = "Do I have PGP keys?"
        $user_3 = "$(xclip -o -selection clipboard"
        $user_4 = "timeout 1 sudo -S -l"
        $user_5 = "You can create a file in /etc/sudoers.d/"
        $user_6 = "The escalation didn't work..."
        $user_7 = "$(command -v doas)"
        $user_8 = "UserShell RealName RecordName Password NFSHomeDirectory"
        $user_9 = "^PASS_MAX_DAYS\\|^PASS_MIN_DAYS\\|^PASS_WARN_AGE\\|^ENCRYPT_METHOD"
    condition:
        5 of them
}

rule Multi_Hacktool_LinPEAS_ng_3ca885bf {
    meta:
        author = "Elastic Security"
        id = "3ca885bf-c737-4df7-a818-9cdeb49560a4"
        fingerprint = "1817bb75c9ce29ef72a6cdd2fd1d2c568b59f5d180ae7197a00d30f8af070bd4"
        creation_date = "2022-12-22"
        last_modified = "2026-05-22"
        description = "LinPEAS detection based on the User info module"
        threat_name = "Multi.Hacktool.LinPEAS-ng"
        reference_sample = "593333df3a1e109c73e8823e3929d52a7fc79a3064eb62004f33f11daca10d0b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $user_0 = "Current user Login and Logout hooks" base64
        $user_1 = "/var/db/SystemKey" base64
        $user_2 = "Do I have PGP keys?" base64
        $user_3 = "$(xclip -o -selection clipboard" base64
        $user_4 = "timeout 1 sudo -S -l" base64
        $user_5 = "You can create a file in /etc/sudoers.d/" base64
        $user_6 = "The escalation didn't work..." base64
        $user_7 = "$(command -v doas)" base64
        $user_8 = "UserShell RealName RecordName Password NFSHomeDirectory" base64
        $user_9 = "^PASS_MAX_DAYS\\|^PASS_MIN_DAYS\\|^PASS_WARN_AGE\\|^ENCRYPT_METHOD" base64
    condition:
        5 of them
}

rule Multi_Hacktool_LinPEAS_ng_1aa3948b {
    meta:
        author = "Elastic Security"
        id = "1aa3948b-a742-40d1-9f06-7f33260206a7"
        fingerprint = "4b2367262369a0dfe1320e9d4f60a7736c47ef6cefab3966561d8746605ee14f"
        creation_date = "2022-12-22"
        last_modified = "2026-05-22"
        description = "LinPEAS detection based on the Software info module"
        threat_name = "Multi.Hacktool.LinPEAS-ng"
        reference_sample = "cc3e69418622499a21248c762373642eb2a2b1073767f22f0dd0f65d0def94a5"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $software_0 = "Installed Compilers"
        $software_1 = "$(command -v pkg 2>/dev/null)"
        $software_2 = "$(command -v mysqladmin)"
        $software_3 = "MySQL version"
        $software_4 = "SELECT User,Host,authentication_string FROM"
        $software_5 = "Some certificates were found (out limited):"
        $software_6 = "keyinfo --list"
        $software_7 = "You could use SSSDKCMExtractor to"
        $software_8 = "LS_USER\\|LS_GROUP"
        $software_9 = "Searching tmux sessions"
    condition:
        5 of them
}

rule Multi_Hacktool_LinPEAS_ng_3e7102db {
    meta:
        author = "Elastic Security"
        id = "3e7102db-69e1-45f1-8258-7a1a40e95e45"
        fingerprint = "098396bdcd0b0f83d8064ec4bd26974abdcf5b1d5bb2abd0ef748cf788c5526e"
        creation_date = "2022-12-22"
        last_modified = "2026-05-22"
        description = "LinPEAS detection based on the Software info module"
        threat_name = "Multi.Hacktool.LinPEAS-ng"
        reference_sample = "593333df3a1e109c73e8823e3929d52a7fc79a3064eb62004f33f11daca10d0b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $software_0 = "Installed Compilers" base64
        $software_1 = "$(command -v pkg 2>/dev/null)" base64
        $software_2 = "$(command -v mysqladmin)" base64
        $software_3 = "MySQL version" base64
        $software_4 = "SELECT User,Host,authentication_string FROM" base64
        $software_5 = "Some certificates were found (out limited):" base64
        $software_6 = "keyinfo --list" base64
        $software_7 = "You could use SSSDKCMExtractor to" base64
        $software_8 = "LS_USER\\|LS_GROUP" base64
        $software_9 = "Searching tmux sessions" base64
    condition:
        5 of them
}

rule Multi_Hacktool_LinPEAS_ng_a5688824 {
    meta:
        author = "Elastic Security"
        id = "a5688824-9b13-4497-bce7-80362d68a4d5"
        fingerprint = "ae86f4b5040f667b0801ef771a20ffe89543d26935e0ed00f4e8827a7ad2b95a"
        creation_date = "2022-12-22"
        last_modified = "2026-05-22"
        description = "LinPEAS detection based on the Files info module"
        threat_name = "Multi.Hacktool.LinPEAS-ng"
        reference_sample = "cc3e69418622499a21248c762373642eb2a2b1073767f22f0dd0f65d0def94a5"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $files_0 = "You have write privileges over"
        $files_1 = "-perm -4000 -type f ! -path"
        $files_2 = "You own the SUID file:"
        $files_3 = "(Unknown SUID binary!)"
        $files_4 = "open|access|no such file"
        $files_5 = "Checking misconfigurations of"
        $files_6 = "$(command -v capsh)"
        $files_7 = "Current env capabilities:"
        $files_8 = "find $HOMESEARCH -user root 2>/dev/null"
        $files_9 = "find /var/mail/ /var/spool/mail/ /private/var/mail -type f -ls"
    condition:
        5 of them
}

rule Multi_Hacktool_LinPEAS_ng_ad70184f {
    meta:
        author = "Elastic Security"
        id = "ad70184f-4f91-4eb4-9efc-6afd4058e432"
        fingerprint = "3ee469f99797ad0de08abd89fa6634a464b26894023a45abf8d7f8f0e758e7f3"
        creation_date = "2022-12-22"
        last_modified = "2026-05-22"
        description = "LinPEAS detection based on the Files info module"
        threat_name = "Multi.Hacktool.LinPEAS-ng"
        reference_sample = "593333df3a1e109c73e8823e3929d52a7fc79a3064eb62004f33f11daca10d0b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $files_0 = "You have write privileges over" base64
        $files_1 = "-perm -4000 -type f ! -path" base64
        $files_2 = "You own the SUID file:" base64
        $files_3 = "(Unknown SUID binary!)" base64
        $files_4 = "open|access|no such file" base64
        $files_5 = "Checking misconfigurations of" base64
        $files_6 = "$(command -v capsh)" base64
        $files_7 = "Current env capabilities:" base64
        $files_8 = "find $HOMESEARCH -user root 2>/dev/null" base64
        $files_9 = "find /var/mail/ /var/spool/mail/ /private/var/mail -type f -ls" base64
    condition:
        5 of them
}

rule Multi_Hacktool_LinPEAS_ng_acc02df3 {
    meta:
        author = "Elastic Security"
        id = "acc02df3-8a22-4fe7-83ec-6810b7933d7a"
        fingerprint = "f55005da8a884e05627a511d8aa065ffdac40a947293a95bd754eda268e407c6"
        creation_date = "2022-12-22"
        last_modified = "2026-05-22"
        description = "LinPEAS detection based on the Base module"
        threat_name = "Multi.Hacktool.LinPEAS-ng"
        reference_sample = "cc3e69418622499a21248c762373642eb2a2b1073767f22f0dd0f65d0def94a5"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $base_0 = "$(printf '\\033')"
        $base_1 = "Enumerate and search Privilege Escalation vectors."
        $base_2 = "grep -c processor /proc/cpuinfo"
        $base_3 = "Do you like PEASS?"
        $base_4 = "RED/YELLOW: 95% a PE vector"
        $base_5 = "\\(root\\)|\\(shadow\\)|\\(admin\\)|\\(video\\)|\\(adm\\)|\\(wheel\\)|\\(auth\\)"
        $base_6 = "peass{SUIDVB1_HERE}"
        $base_7 = "file|free|main|more|read|split|write"
        $base_8 = "cap_sys_admin:mount|python"
        $base_9 = "timeout 1 su $(whoami) -c whoami"
    condition:
        5 of them
}

rule Multi_Hacktool_LinPEAS_ng_02c12676 {
    meta:
        author = "Elastic Security"
        id = "02c12676-4101-44ae-be7c-d93717d04b0a"
        fingerprint = "e2e1233f5c9f24da37e1abf2c216c31505fd3f061bd0228c2c6da9036f3c863b"
        creation_date = "2022-12-22"
        last_modified = "2026-05-22"
        description = "LinPEAS detection based on the Base module"
        threat_name = "Multi.Hacktool.LinPEAS-ng"
        reference_sample = "593333df3a1e109c73e8823e3929d52a7fc79a3064eb62004f33f11daca10d0b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $base_0 = "$(printf '\\033')" base64
        $base_1 = "Enumerate and search Privilege Escalation vectors." base64
        $base_2 = "grep -c processor /proc/cpuinfo" base64
        $base_3 = "Do you like PEASS?" base64
        $base_4 = "RED/YELLOW: 95% a PE vector" base64
        $base_5 = "\\(root\\)|\\(shadow\\)|\\(admin\\)|\\(video\\)|\\(adm\\)|\\(wheel\\)|\\(auth\\)" base64
        $base_6 = "peass{SUIDVB1_HERE}" base64
        $base_7 = "file|free|main|more|read|split|write" base64
        $base_8 = "cap_sys_admin:mount|python" base64
        $base_9 = "timeout 1 su $(whoami) -c whoami" base64
    condition:
        5 of them
}

