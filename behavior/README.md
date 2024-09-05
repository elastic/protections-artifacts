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
| production-rules-linux-v1 | 1.0.70 | bf8e7219811516795bd3e7ce6f45ecad6d32f3e4c7ad014afaf08701f04895d1 |
| production-rules-macos-v1 | 1.0.70 | e700445b82ed692ea16c4e05a6bce60b6eac148f0c5730e35f17b68328627b20 |
| production-rules-windows-v1 | 1.0.70 | 5a56b70ef04e42d559c10560cdf1946373ee920f4a432530d674a3a958e6c668 |

### Rules Summary per Tactic

Note: New Production Rules since last version ('1.0.70', '1.0.69') by OS/MITRE Tactic.
| Tactic          |   Windows |   Linux |   macOS |   Total by Tactic |
|-----------------|-----------|---------|---------|-------------------|
| Defense Evasion |         7 |       0 |       4 |                11 |
| Execution       |         0 |       0 |       4 |                 4 |
| Persistence     |         1 |       0 |       1 |                 2 |
| Total by OS     |         8 |       0 |       9 |                17 |

Note: Latest Total Production Rules by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |        11 |       0 |       5 |                16 |
| Command and Control  |        31 |       4 |      26 |                61 |
| Credential Access    |        42 |       3 |      24 |                69 |
| Defense Evasion      |       246 |      15 |      47 |               308 |
| Discovery            |         6 |       0 |       4 |                10 |
| Execution            |        61 |      20 |      66 |               147 |
| Exfiltration         |         0 |       0 |       1 |                 1 |
| Impact               |        17 |       2 |       2 |                21 |
| Initial Access       |        50 |       2 |       2 |                54 |
| Lateral Movement     |         8 |       1 |       1 |                10 |
| Persistence          |        54 |      21 |      18 |                93 |
| Privilege Escalation |        58 |       7 |       8 |                73 |
| Total by OS          |       584 |      75 |     204 |               863 |



### The Zen of Security Rules

We incorporate the [Zen of Security Rules](https://zenofsecurity.io/rules) into all of our rule development and planning. We strive to follow these principles to ensure practical rule design for resiliency at scale. 

