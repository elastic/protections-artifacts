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

Note: New Production Rules since last version ('1.0.16', '1.0.13') by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Command and Control  |         1 |       0 |       0 |                 1 |
| Credential Access    |         1 |       0 |       0 |                 1 |
| Defense Evasion      |         3 |       0 |       0 |                 3 |
| Execution            |         1 |       0 |       0 |                 1 |
| Initial Access       |         1 |       0 |       0 |                 1 |
| Persistence          |         3 |       0 |       1 |                 4 |
| Privilege Escalation |         1 |       0 |       0 |                 1 |
| Total by OS          |        11 |       0 |       1 |                12 |

Note: Latest Total Production Rules by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Command and Control  |        11 |       0 |       4 |                15 |
| Credential Access    |        25 |       0 |       4 |                29 |
| Defense Evasion      |        65 |       0 |      10 |                75 |
| Discovery            |         2 |       1 |       2 |                 5 |
| Execution            |        29 |       4 |       9 |                42 |
| Impact               |        13 |       1 |       1 |                15 |
| Initial Access       |        31 |       0 |       2 |                33 |
| Lateral Movement     |         5 |       0 |       1 |                 6 |
| Persistence          |        21 |       0 |       7 |                28 |
| Privilege Escalation |        38 |       2 |       5 |                45 |
| Total by OS          |       240 |       8 |      45 |               293 |

### Licensing
These rules are licensed under the Elastic License v2. All rules have been designed to be used in the context of the Elastic Endpoint within the Elastic Security application.
