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
| production-rules-linux-v1 | 1.0.94 | 1cc0f98eb95d5f4650b513fa7f42eaab89b4aa837c454dc90c27afb20bf5ae18 |
| production-rules-macos-v1 | 1.0.94 | 738a367541a5751c03c695cbe9c6fe896e9d33e9d96783936c8850fd02a1b3c5 |
| production-rules-windows-v1 | 1.0.94 | 92432fd41ca4f309bc4e2fa13637a0c8c877459baed40eeaad1ec95cabde8d26 |

### Rules Summary per Tactic

Note: New Production Rules since last version ('1.0.94', '1.0.93') by OS/MITRE Tactic.

| Tactic              |   Windows |   Linux |   macOS |   Total by Tactic |
|---------------------|-----------|---------|---------|-------------------|
| Command and Control |         0 |       1 |       0 |                 1 |
| Defense Evasion     |         0 |       2 |       0 |                 2 |
| Total by OS         |         0 |       3 |       0 |                 3 |

Note: Latest Total Production Rules by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |         9 |       0 |       8 |                17 |
| Command and Control  |        33 |      13 |      37 |                83 |
| Credential Access    |        46 |       4 |      30 |                80 |
| Defense Evasion      |       274 |      49 |      53 |               376 |
| Discovery            |         7 |       1 |       4 |                12 |
| Execution            |        88 |      46 |      78 |               212 |
| Exfiltration         |         0 |       0 |       1 |                 1 |
| Impact               |        18 |       6 |       2 |                26 |
| Initial Access       |        55 |       1 |       2 |                58 |
| Lateral Movement     |        10 |       1 |       1 |                12 |
| Persistence          |        56 |      34 |      23 |               113 |
| Privilege Escalation |        66 |       9 |       8 |                83 |
| Total by OS          |       662 |     164 |     247 |              1073 |

### The Zen of Security Rules

We incorporate the [Zen of Security Rules](https://zenofsecurity.io/rules) into all of our rule development and planning. We strive to follow these principles to ensure practical rule design for resiliency at scale. 
