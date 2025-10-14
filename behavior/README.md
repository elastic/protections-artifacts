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
| production-rules-linux-v1 | 1.0.99 | fbb1608127b6680d0d84a84121e3defc144d15f539a0c7aba5abba2011ba24a4 |
| production-rules-macos-v1 | 1.0.99 | 0147bbf48b95f36330a528077cad9c665e4a5f4b4c98a4c47a7633318715828e |
| production-rules-windows-v1 | 1.0.99 | 608fb0db8fa37493c5cdcbb4e319ff911937bb8b021efc3efb7d58d1cf88d3bf |

### Rules Summary per Tactic

Note: New Production Rules since last version ('1.0.99', '1.0.98') by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Command and Control  |         0 |       0 |       2 |                 2 |
| Credential Access    |         0 |       0 |       1 |                 1 |
| Defense Evasion      |         4 |       0 |       1 |                 5 |
| Discovery            |        12 |       0 |       0 |                12 |
| Execution            |         2 |       2 |       3 |                 7 |
| Impact               |         1 |       0 |       0 |                 1 |
| Privilege Escalation |         1 |       0 |       0 |                 1 |
| Total by OS          |        20 |       2 |       7 |                29 |

Note: Latest Total Production Rules by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |        11 |       0 |       9 |                20 |
| Command and Control  |        37 |      14 |      41 |                92 |
| Credential Access    |        46 |       4 |      31 |                81 |
| Defense Evasion      |       298 |      50 |      58 |               406 |
| Discovery            |        19 |       1 |       4 |                24 |
| Execution            |        90 |      56 |      92 |               238 |
| Exfiltration         |         0 |       0 |       1 |                 1 |
| Impact               |        19 |       6 |       2 |                27 |
| Initial Access       |        59 |       1 |       2 |                62 |
| Lateral Movement     |        10 |       2 |       2 |                14 |
| Persistence          |        57 |      34 |      25 |               116 |
| Privilege Escalation |        69 |      13 |       8 |                90 |
| Total by OS          |       715 |     181 |     275 |              1171 |

### The Zen of Security Rules

We incorporate the [Zen of Security Rules](https://zenofsecurity.io/rules) into all of our rule development and planning. We strive to follow these principles to ensure practical rule design for resiliency at scale. 
