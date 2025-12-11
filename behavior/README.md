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
| production-rules-linux-v1 | 1.0.104 | fe7c26b04f2901f90aad354e9265c297f3f5ddb8b3077977baf2618274533490 |
| production-rules-macos-v1 | 1.0.104 | e845e9b2f717c7a993acadc28f7b465fae1a302c26f0baec60bec8e91fdfa425 |
| production-rules-windows-v1 | 1.0.104 | 2c14dbccf76b6995f792cca0267c6ea89615b30b57b60a069e1fb21fab46b731 |

### Rules Summary per Tactic

Note: New Production Rules since last version ('1.0.104', '1.0.103') by OS/MITRE Tactic.

| Tactic          |   Windows |   Linux |   macOS |   Total by Tactic |
|-----------------|-----------|---------|---------|-------------------|
| Defense Evasion |         1 |       0 |       0 |                 1 |
| Execution       |         0 |       2 |       0 |                 2 |
| Total by OS     |         1 |       2 |       0 |                 3 |

Note: Latest Total Production Rules by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |        11 |       0 |      10 |                21 |
| Command and Control  |        38 |      13 |      45 |                96 |
| Credential Access    |        49 |       3 |      32 |                84 |
| Defense Evasion      |       307 |      49 |      58 |               414 |
| Discovery            |        20 |       1 |       4 |                25 |
| Execution            |        92 |      64 |      99 |               255 |
| Exfiltration         |         0 |       0 |       2 |                 2 |
| Impact               |        19 |       6 |       2 |                27 |
| Initial Access       |        62 |       1 |       2 |                65 |
| Lateral Movement     |        10 |       2 |       2 |                14 |
| Persistence          |        57 |      34 |      25 |               116 |
| Privilege Escalation |        69 |      15 |       8 |                92 |
| Total by OS          |       734 |     188 |     289 |              1211 |

### The Zen of Security Rules

We incorporate the [Zen of Security Rules](https://zenofsecurity.io/rules) into all of our rule development and planning. We strive to follow these principles to ensure practical rule design for resiliency at scale. 
