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

<!-- python -m endpoint_rules rule-stats-summary --release-version latest 1.0.2 -->
Note: New Production Rules since last version ('latest', '1.0.2') by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Credential Access    |        16 |       0 |       4 |                20 |
| Discovery            |         0 |       1 |       2 |                 3 |
| Execution            |         8 |       0 |       0 |                 8 |
| Defense Evasion      |        12 |       0 |       3 |                15 |
| Impact               |         3 |       0 |       0 |                 3 |
| Privilege Escalation |         4 |       1 |       1 |                 6 |
| Initial Access       |         5 |       0 |       0 |                 5 |
| Command and Control  |         3 |       0 |       0 |                 3 |
| Lateral Movement     |         3 |       0 |       1 |                 4 |
| Persistence          |         1 |       0 |       1 |                 2 |
| Total by OS          |        55 |       2 |      12 |                69 |

Note: Latest Total Production Rules by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Execution            |        22 |       4 |       8 |                34 |
| Credential Access    |        21 |       0 |       4 |                25 |
| Persistence          |        15 |       0 |       2 |                17 |
| Discovery            |         2 |       1 |       2 |                 5 |
| Privilege Escalation |        33 |       2 |       2 |                37 |
| Defense Evasion      |        42 |       0 |       3 |                45 |
| Impact               |        10 |       1 |       1 |                12 |
| Initial Access       |        22 |       0 |       0 |                22 |
| Lateral Movement     |         5 |       0 |       1 |                 6 |
| Command and Control  |         8 |       0 |       1 |                 9 |
| Total by OS          |       180 |       8 |      24 |               212 |


### Licensing
These rules are licensed under the Elastic License v2. All rules have been designed to be used in the context of the Elastic Endpoint within the Elastic Security application.
