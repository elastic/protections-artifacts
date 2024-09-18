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
| production-rules-linux-v1 | 1.0.71 | d1bdc888f2aae01f84c877bc583159a4e23b0d30ec3797eb4dc63918d6df7321 |
| production-rules-macos-v1 | 1.0.71 | 5766bb6f8ff6985e9d02fce87314ed7b51240bd6706b19e482eaca6c8c1ac393 |
| production-rules-windows-v1 | 1.0.71 | ac3d85b0759444416767e7f6150eb36cba8a22acd6dc90e454cf5d833e45242c |

### Rules Summary per Tactic

Note: New Production Rules since last version ('1.0.71', '1.0.70') by OS/MITRE Tactic.
| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Command and Control  |         0 |       3 |       1 |                 4 |
| Defense Evasion      |         2 |       3 |       1 |                 6 |
| Discovery            |         1 |       1 |       0 |                 2 |
| Execution            |         1 |       2 |       4 |                 7 |
| Initial Access       |         2 |       0 |       0 |                 2 |
| Persistence          |         0 |       3 |       1 |                 4 |
| Privilege Escalation |         0 |       1 |       0 |                 1 |
| Total by OS          |         6 |      13 |       7 |                26 |

Note: Latest Total Production Rules by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |        11 |       0 |       5 |                16 |
| Command and Control  |        31 |       6 |      27 |                64 |
| Credential Access    |        42 |       3 |      24 |                69 |
| Defense Evasion      |       248 |      17 |      48 |               313 |
| Discovery            |         7 |       1 |       4 |                12 |
| Execution            |        62 |      22 |      70 |               154 |
| Exfiltration         |         0 |       0 |       1 |                 1 |
| Impact               |        17 |       2 |       2 |                21 |
| Initial Access       |        52 |       2 |       2 |                56 |
| Lateral Movement     |         8 |       1 |       1 |                10 |
| Persistence          |        54 |      24 |      19 |                97 |
| Privilege Escalation |        58 |       8 |       8 |                74 |
| Total by OS          |       590 |      86 |     211 |               887 |



### The Zen of Security Rules

We incorporate the [Zen of Security Rules](https://zenofsecurity.io/rules) into all of our rule development and planning. We strive to follow these principles to ensure practical rule design for resiliency at scale. 

