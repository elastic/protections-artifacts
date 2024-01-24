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
| production-rules-linux-v1 | 1.0.52 | c2c65c62131bb4eb235baec59952595ed23231cc13700572be5ad7add4526613 |
| production-rules-macos-v1 | 1.0.52 | 802ebd860463412806bb534b3f994dae703969254cacea3b09b93e9d5697ec75 |
| production-rules-windows-v1 | 1.0.52 | 67a5c8226681a54b3be90d20afc3adcf9011f82f87b01316f9bb7237f2139bc9 |

### Rules Summary per Tactic

Note: New Production Rules since last version ('1.0.52', '1.0.51') by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Command and Control  |         0 |       0 |       1 |                 1 |
| Credential Access    |         0 |       0 |       1 |                 1 |
| Defense Evasion      |         1 |       0 |       1 |                 2 |
| Privilege Escalation |         3 |       0 |       0 |                 3 |
| Total by OS          |         4 |       0 |       3 |                 7 |

Note: Latest Total Production Rules by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |         4 |       0 |       1 |                 5 |
| Command and Control  |        24 |       3 |      23 |                50 |
| Credential Access    |        37 |       3 |      19 |                59 |
| Defense Evasion      |       201 |       7 |      37 |               245 |
| Discovery            |         4 |       0 |       3 |                 7 |
| Execution            |        50 |      10 |      43 |               103 |
| Exfiltration         |         0 |       0 |       1 |                 1 |
| Impact               |        14 |       2 |       2 |                18 |
| Initial Access       |        44 |       1 |       2 |                47 |
| Lateral Movement     |         8 |       1 |       1 |                10 |
| Persistence          |        49 |       2 |      17 |                68 |
| Privilege Escalation |        52 |       5 |       7 |                64 |
| Total by OS          |       487 |      34 |     156 |               677 |
