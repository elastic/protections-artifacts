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

Note: New Production Rules since last version ('1.0.28', '1.0.27') by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Defense Evasion      |         0 |       0 |       4 |                 4 |
| Execution            |         1 |       0 |       2 |                 3 |
| Exfiltration         |         0 |       0 |       1 |                 1 |
| Persistence          |         0 |       0 |       3 |                 3 |
| Privilege Escalation |         1 |       0 |       0 |                 1 |
| Total by OS          |         2 |       0 |      10 |                12 |

Note: Latest Total Production Rules by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Command and Control  |        17 |       2 |       5 |                24 |
| Credential Access    |        30 |       0 |       6 |                36 |
| Defense Evasion      |        90 |       2 |      17 |               109 |
| Discovery            |         3 |       0 |       1 |                 4 |
| Execution            |        36 |       5 |      15 |                56 |
| Exfiltration         |         0 |       0 |       1 |                 1 |
| Impact               |        13 |       2 |       2 |                17 |
| Initial Access       |        37 |       1 |       2 |                40 |
| Lateral Movement     |         8 |       0 |       1 |                 9 |
| Persistence          |        36 |       0 |      12 |                48 |
| Privilege Escalation |        45 |       2 |       6 |                53 |
| Total by OS          |       315 |      14 |      68 |               397 |
