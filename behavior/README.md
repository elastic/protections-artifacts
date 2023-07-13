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

### Rules Summary per Tactic

Note: New Production Rules since last version ('1.0.38', '1.0.30') by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |         1 |       0 |       0 |                 1 |
| Command and Control  |         1 |       0 |       4 |                 5 |
| Credential Access    |         2 |       0 |       2 |                 4 |
| Defense Evasion      |        43 |       0 |      11 |                54 |
| Discovery            |         0 |       0 |       1 |                 1 |
| Execution            |         6 |       0 |       9 |                15 |
| Initial Access       |         5 |       0 |       0 |                 5 |
| Persistence          |         2 |       0 |       2 |                 4 |
| Privilege Escalation |         1 |       0 |       0 |                 1 |
| Total by OS          |        61 |       0 |      29 |                90 |

Note: Latest Total Production Rules by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |         1 |       0 |       0 |                 1 |
| Command and Control  |        18 |       2 |      10 |                30 |
| Credential Access    |        36 |       0 |       8 |                44 |
| Defense Evasion      |       134 |       2 |      32 |               168 |
| Discovery            |         4 |       0 |       2 |                 6 |
| Execution            |        44 |       5 |      24 |                73 |
| Exfiltration         |         0 |       0 |       1 |                 1 |
| Impact               |        13 |       2 |       2 |                17 |
| Initial Access       |        42 |       1 |       2 |                45 |
| Lateral Movement     |         8 |       0 |       1 |                 9 |
| Persistence          |        44 |       0 |      14 |                58 |
| Privilege Escalation |        46 |       2 |       7 |                55 |
| Total by OS          |       390 |      14 |     103 |               507 |
