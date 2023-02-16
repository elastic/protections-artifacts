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

Note: New Production Rules since last version ('1.0.24', '1.0.21') by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Command and Control  |         2 |       1 |       0 |                 3 |
| Credential Access    |         3 |       0 |       0 |                 3 |
| Defense Evasion      |         6 |       1 |       1 |                 8 |
| Execution            |         0 |       1 |       0 |                 1 |
| Initial Access       |         1 |       1 |       0 |                 2 |
| Lateral Movement     |         1 |       0 |       0 |                 1 |
| Persistence          |         5 |       0 |       0 |                 5 |
| Privilege Escalation |         1 |       0 |       1 |                 2 |
| Total by OS          |        19 |       4 |       2 |                25 |

Note: Latest Total Production Rules by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Command and Control  |        15 |       2 |       4 |                21 |
| Credential Access    |        28 |       0 |       3 |                31 |
| Defense Evasion      |        83 |       2 |      11 |                96 |
| Discovery            |         3 |       1 |       2 |                 6 |
| Execution            |        35 |       5 |       9 |                49 |
| Impact               |        13 |       1 |       1 |                15 |
| Initial Access       |        35 |       1 |       2 |                38 |
| Lateral Movement     |         7 |       0 |       1 |                 8 |
| Persistence          |        32 |       0 |       6 |                38 |
| Privilege Escalation |        42 |       2 |       6 |                50 |
| Total by OS          |       293 |      14 |      45 |               352 |
### Licensing
These rules are licensed under the Elastic License v2. All rules have been designed to be used in the context of the Elastic Endpoint within the Elastic Security application.
