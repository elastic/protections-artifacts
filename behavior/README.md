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
| production-rules-linux-v1 | 1.0.72 | f0798c0e5f2c470f1cb6c32be094af4ab0dd97699b75677b6a980a1676467bfb |
| production-rules-macos-v1 | 1.0.72 | 9d86d62a056542724a4644f6e7d4a7ac3de572efbba79c922a96107e4c12137a |
| production-rules-windows-v1 | 1.0.72 | bbfd9fb090eee3c1ff40a2d50c1a16f459e2dfe1e6e5365a96aab0a10fd1f3c4 |

### Rules Summary per Tactic

Note: New Production Rules since last version ('1.0.72', '1.0.71') by OS/MITRE Tactic.
| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Command and Control  |         0 |       1 |       0 |                 1 |
| Defense Evasion      |         2 |       7 |       0 |                 9 |
| Persistence          |         0 |       1 |       0 |                 1 |
| Privilege Escalation |         1 |       0 |       0 |                 1 |
| Total by OS          |         3 |       9 |       0 |                12 |

Note: Latest Total Production Rules by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |        11 |       0 |       5 |                16 |
| Command and Control  |        31 |       7 |      27 |                65 |
| Credential Access    |        42 |       3 |      24 |                69 |
| Defense Evasion      |       250 |      24 |      48 |               322 |
| Discovery            |         7 |       1 |       4 |                12 |
| Execution            |        62 |      22 |      70 |               154 |
| Exfiltration         |         0 |       0 |       1 |                 1 |
| Impact               |        17 |       2 |       2 |                21 |
| Initial Access       |        52 |       2 |       2 |                56 |
| Lateral Movement     |         8 |       1 |       1 |                10 |
| Persistence          |        54 |      25 |      19 |                98 |
| Privilege Escalation |        59 |       8 |       8 |                75 |
| Total by OS          |       593 |      95 |     211 |               899 |



### The Zen of Security Rules

We incorporate the [Zen of Security Rules](https://zenofsecurity.io/rules) into all of our rule development and planning. We strive to follow these principles to ensure practical rule design for resiliency at scale. 

