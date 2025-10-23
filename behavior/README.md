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
| production-rules-linux-v1 | 1.0.100 | 1d2cf747b4ef21f397a06f6f3c61d48ad88ff3b923690ab411a2bb183f3cb8f6 |
| production-rules-macos-v1 | 1.0.100 | 100640ea6af1be6250e54209b4043a18e5ddd95232ea15fb1a30d5a499047af6 |
| production-rules-windows-v1 | 1.0.100 | 4d36c59bfb415550c22495b3800dfee4be6931704baaf17ae5a8d44d30ad83ff |

### Rules Summary per Tactic

Note: New Production Rules since last version ('1.0.100', '1.0.99') by OS/MITRE Tactic.

| Tactic              |   Windows |   Linux |   macOS |   Total by Tactic |
|---------------------|-----------|---------|---------|-------------------|
| Command and Control |         0 |       0 |       1 |                 1 |
| Credential Access   |         1 |       0 |       0 |                 1 |
| Defense Evasion     |         1 |       1 |       0 |                 2 |
| Discovery           |         1 |       0 |       0 |                 1 |
| Execution           |         1 |       0 |       1 |                 2 |
| Initial Access      |         1 |       0 |       0 |                 1 |
| Total by OS         |         5 |       1 |       2 |                 8 |

Note: Latest Total Production Rules by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |        11 |       0 |       9 |                20 |
| Command and Control  |        37 |      13 |      42 |                92 |
| Credential Access    |        47 |       4 |      31 |                82 |
| Defense Evasion      |       299 |      50 |      58 |               407 |
| Discovery            |        20 |       1 |       4 |                25 |
| Execution            |        91 |      56 |      93 |               240 |
| Exfiltration         |         0 |       0 |       1 |                 1 |
| Impact               |        19 |       6 |       2 |                27 |
| Initial Access       |        60 |       1 |       2 |                63 |
| Lateral Movement     |        10 |       2 |       2 |                14 |
| Persistence          |        57 |      34 |      25 |               116 |
| Privilege Escalation |        69 |      13 |       8 |                90 |
| Total by OS          |       720 |     180 |     277 |              1177 |

### The Zen of Security Rules

We incorporate the [Zen of Security Rules](https://zenofsecurity.io/rules) into all of our rule development and planning. We strive to follow these principles to ensure practical rule design for resiliency at scale. 
