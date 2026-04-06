## Elastic Security Malicious Behavior Protection Rules

Prebuilt high signal [EQL](https://www.elastic.co/guide/en/elasticsearch/reference/current/eql.html) rules that runs on the endpoint to disrupt malicious behavior, this layer of prevention equips Elastic Agent to protect Linux, Windows, and macOS hosts from a broad range of attack techniques with a major focus on the following tactics :

- [Initial Access](https://attack.mitre.org/tactics/TA0001/)
- [Execution](https://attack.mitre.org/tactics/TA0002/)
- [Privilege Escalation](https://attack.mitre.org/tactics/TA0004/)
- [Defense Evasion](https://attack.mitre.org/tactics/TA0005/)
- [Credential Access](https://attack.mitre.org/tactics/TA0006/)
- [Impact](https://attack.mitre.org/tactics/TA0040/)

Prevention is achieved by pairing post-execution analytics with response actions to kill a specific process or a full process tree tailored to stop the adversary at the initial stages of the attack. Each protection rule is mapped to the most relevant [MITRE ATT&CK](https://attack.mitre.org/) tactic,  technique and subtechnique.

The true positive rate that we aim to maintain is at least 70%, thus we prioritize analytics logic precision to reduce detection scope via prevention.

Another example of our commitment to openness in security is our existing public [Detection Rules](https://github.com/elastic/detection-rules) repository where we share [EQL](https://www.elastic.co/guide/en/elasticsearch/reference/current/eql.html) rules that run on the SIEM side, and that have a broader detection logic which make them more suitable for detection and hunting.


### Latest Release

| artifact             | version        | hash            |
| -------------------- | -------------- | --------------- |
| production-rules-linux-v1 | 1.0.113 | 8bdf5d935f6543979795c03949a45165f7a589253b92236e0189cae32ec08232 |
| production-rules-macos-v1 | 1.0.113 | 0d376ef9df53e154c95ef394a52baa44967fa0692a912180302f5b8eaceac4b6 |
| production-rules-windows-v1 | 1.0.113 | 99469de01670e7fccc73b9ba55c56d40aa60db0ece882a951d280b063decb400 |

### Rules Summary per Tactic

Note: New Production Rules since last version ('1.0.113', '1.0.112') by OS/MITRE Tactic.

No 'production' rule updates have been made between versions 1.0.113 and 1.0.112

Note: Latest Total Production Rules by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |        12 |       0 |       8 |                20 |
| Command and Control  |        39 |      11 |      42 |                92 |
| Credential Access    |        52 |       7 |      34 |                93 |
| Defense Evasion      |       320 |      44 |      59 |               423 |
| Discovery            |        20 |       1 |       1 |                22 |
| Execution            |        94 |      58 |     103 |               255 |
| Exfiltration         |         0 |       0 |       2 |                 2 |
| Impact               |        19 |       6 |       2 |                27 |
| Initial Access       |        62 |       1 |       2 |                65 |
| Lateral Movement     |        10 |       2 |       1 |                13 |
| Persistence          |        60 |      25 |      20 |               105 |
| Privilege Escalation |        73 |      14 |       9 |                96 |
| Total by OS          |       761 |     169 |     283 |              1213 |
