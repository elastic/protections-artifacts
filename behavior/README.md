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
| production-rules-linux-v1 | 1.0.76 | a1dd1973c367850578b8f19a660adff60c468d9801354506d30a86d1c525594e |
| production-rules-macos-v1 | 1.0.76 | e0f9fc64bd6eb722476f9adb2e9d9c32c7d2ab1861440f2ceb1a9462ee4a797a |
| production-rules-windows-v1 | 1.0.76 | fcd33d440ff1882a4d5117650e1b8009fc94ea28a8cb0b929baab88c70a273cf |

### Rules Summary per Tactic

Note: New Production Rules since last version ('1.0.76', '1.0.75') by OS/MITRE Tactic.
| Tactic          |   Windows |   Linux |   macOS |   Total by Tactic |
|-----------------|-----------|---------|---------|-------------------|
| Collection      |         0 |       0 |       1 |                 1 |
| Defense Evasion |         0 |       0 |       1 |                 1 |
| Execution       |         0 |       0 |       1 |                 1 |
| Total by OS     |         0 |       0 |       3 |                 3 |

Note: Latest Total Production Rules by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |        11 |       0 |       6 |                17 |
| Command and Control  |        32 |      11 |      27 |                70 |
| Credential Access    |        44 |       4 |      24 |                72 |
| Defense Evasion      |       255 |      42 |      46 |               343 |
| Discovery            |         8 |       1 |       4 |                13 |
| Execution            |        64 |      35 |      71 |               170 |
| Exfiltration         |         0 |       0 |       1 |                 1 |
| Impact               |        18 |       4 |       2 |                24 |
| Initial Access       |        53 |       2 |       2 |                57 |
| Lateral Movement     |         8 |       1 |       1 |                10 |
| Persistence          |        56 |      29 |      17 |               102 |
| Privilege Escalation |        60 |       8 |       8 |                76 |
| Total by OS          |       609 |     137 |     209 |               955 |


### The Zen of Security Rules

We incorporate the [Zen of Security Rules](https://zenofsecurity.io/rules) into all of our rule development and planning. We strive to follow these principles to ensure practical rule design for resiliency at scale. 

