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
| production-rules-linux-v1 | 1.0.80 | 89f0cf962cd80391de3a58c8bf83bcafed5894e272dab17cf0402095f930ea63 |
| production-rules-macos-v1 | 1.0.80 | 9737a2204afdf4d272d09d4400ff4fff0609d07bfb0b2609ef9b8d13455dd106 |
| production-rules-windows-v1 | 1.0.80 | 6d18ae386c799ee23f28058825b651080a1021986fca087a3b4600ef62cd4453 |

### Rules Summary per Tactic

Note: New Production Rules since last version ('1.0.80', '1.0.79') by OS/MITRE Tactic.

| Tactic          |   Windows |   Linux |   macOS |   Total by Tactic |
|-----------------|-----------|---------|---------|-------------------|
| Defense Evasion |         2 |       0 |       0 |                 2 |
| Execution       |         1 |       0 |       0 |                 1 |
| Total by OS     |         3 |       0 |       0 |                 3 |

Note: Latest Total Production Rules by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |        11 |       0 |       5 |                16 |
| Command and Control  |        34 |      11 |      26 |                71 |
| Credential Access    |        45 |       4 |      24 |                73 |
| Defense Evasion      |       265 |      42 |      44 |               351 |
| Discovery            |         8 |       1 |       4 |                13 |
| Execution            |        65 |      35 |      71 |               171 |
| Exfiltration         |         0 |       0 |       1 |                 1 |
| Impact               |        18 |       4 |       2 |                24 |
| Initial Access       |        54 |       2 |       2 |                58 |
| Lateral Movement     |         8 |       1 |       1 |                10 |
| Persistence          |        56 |      29 |      17 |               102 |
| Privilege Escalation |        65 |       8 |       8 |                81 |
| Total by OS          |       629 |     137 |     205 |               971 |


### The Zen of Security Rules

We incorporate the [Zen of Security Rules](https://zenofsecurity.io/rules) into all of our rule development and planning. We strive to follow these principles to ensure practical rule design for resiliency at scale. 
