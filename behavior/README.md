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
| production-rules-linux-v1 | 1.0.79 | 996a760a9dfd15f64419ea3a38a341b8ef37ac8d7c60811891aac743305ebd65 |
| production-rules-macos-v1 | 1.0.79 | be34756a32b592aa86538c8580bbd848b07e839619a2f3b7565071c340dfd27f |
| production-rules-windows-v1 | 1.0.79 | 5aba5bf979505d57b2af9f1295f30edd8f34b50f1099bd3cee8c3e9b7042ed6e |

### Rules Summary per Tactic

Note: New Production Rules since last version ('1.0.78', '1.0.77') by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Command and Control  |         2 |       0 |       0 |                 2 |
| Credential Access    |         1 |       0 |       0 |                 1 |
| Defense Evasion      |         5 |       0 |       0 |                 5 |
| Privilege Escalation |         4 |       0 |       0 |                 4 |
| Total by OS          |        12 |       0 |       0 |                12 |

Note: Latest Total Production Rules by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |        11 |       0 |       6 |                17 |
| Command and Control  |        34 |      11 |      27 |                72 |
| Credential Access    |        45 |       4 |      24 |                73 |
| Defense Evasion      |       263 |      42 |      44 |               349 |
| Discovery            |         8 |       1 |       4 |                13 |
| Execution            |        64 |      35 |      71 |               170 |
| Exfiltration         |         0 |       0 |       1 |                 1 |
| Impact               |        18 |       4 |       2 |                24 |
| Initial Access       |        54 |       2 |       2 |                58 |
| Lateral Movement     |         8 |       1 |       1 |                10 |
| Persistence          |        56 |      29 |      17 |               102 |
| Privilege Escalation |        65 |       8 |       8 |                81 |
| Total by OS          |       626 |     137 |     207 |               970 |
