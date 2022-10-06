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

Note: New Production Rules since last version ('latest', '1.0.10') by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Command and Control  |         1 |       0 |       1 |                 2 |
| Credential Access    |         3 |       0 |       0 |                 3 |
| Defense Evasion      |        11 |       0 |       4 |                15 |
| Execution            |         4 |       0 |       1 |                 5 |
| Impact               |         3 |       0 |       0 |                 3 |
| Initial Access       |         6 |       0 |       1 |                 7 |
| Persistence          |         2 |       0 |       2 |                 4 |
| Privilege Escalation |         4 |       0 |       2 |                 6 |
| Total by OS          |        34 |       0 |      11 |                45 |

Note: Latest Total Production Rules by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Command and Control  |         9 |       0 |       2 |                11 |
| Credential Access    |        24 |       0 |       4 |                28 |
| Defense Evasion      |        53 |       0 |       7 |                60 |
| Discovery            |         2 |       1 |       2 |                 5 |
| Execution            |        26 |       4 |       9 |                39 |
| Impact               |        13 |       1 |       1 |                15 |
| Initial Access       |        28 |       0 |       1 |                29 |
| Lateral Movement     |         5 |       0 |       1 |                 6 |
| Persistence          |        17 |       0 |       4 |                21 |
| Privilege Escalation |        37 |       2 |       4 |                43 |
| Total by OS          |       214 |       8 |      35 |               257 |

### Licensing
These rules are licensed under the Elastic License v2. All rules have been designed to be used in the context of the Elastic Endpoint within the Elastic Security application.
