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

Note: New Production Rules since last version ('1.0.25', '1.0.24') by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Command and Control  |         2 |       0 |       1 |                 3 |
| Credential Access    |         1 |       0 |       3 |                 4 |
| Defense Evasion      |         2 |       0 |       2 |                 4 |
| Execution            |         0 |       0 |       5 |                 5 |
| Impact               |         0 |       1 |       1 |                 2 |
| Initial Access       |         2 |       0 |       0 |                 2 |
| Persistence          |         0 |       0 |       3 |                 3 |
| Privilege Escalation |         1 |       0 |       0 |                 1 |
| Total by OS          |         8 |       1 |      15 |                24 |

Note: Latest Total Production Rules by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Command and Control  |        17 |       2 |       5 |                24 |
| Credential Access    |        29 |       0 |       6 |                35 |
| Defense Evasion      |        85 |       2 |      13 |               100 |
| Discovery            |         3 |       1 |       2 |                 6 |
| Execution            |        35 |       5 |      14 |                54 |
| Impact               |        13 |       2 |       2 |                17 |
| Initial Access       |        37 |       1 |       2 |                40 |
| Lateral Movement     |         7 |       0 |       1 |                 8 |
| Persistence          |        32 |       0 |       9 |                41 |
| Privilege Escalation |        43 |       2 |       6 |                51 |
| Total by OS          |       301 |      15 |      60 |               376 |
