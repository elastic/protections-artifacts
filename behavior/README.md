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
| production-rules-linux-v1 | 1.0.105 | 08c522ae8ceec86a3cb699d31a0e6711712eade66c370d11bf460f6af5246bb3 |
| production-rules-macos-v1 | 1.0.105 | 2c20f9fc44fcc6e58c86b34032b0d21a0f9c84b05e43ba33c037d874cbb054db |
| production-rules-windows-v1 | 1.0.105 | d90b0229a78845e6a950ed78840e6f5690855176a746f57f34de621950f84b2d |

### Rules Summary per Tactic

Note: New Production Rules since last version ('1.0.105', '1.0.104') by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |         1 |       0 |       0 |                 1 |
| Command and Control  |         2 |       2 |       3 |                 7 |
| Credential Access    |         4 |       4 |       4 |                12 |
| Defense Evasion      |        15 |       2 |       3 |                20 |
| Discovery            |         0 |       1 |       0 |                 1 |
| Execution            |         1 |       6 |       6 |                13 |
| Persistence          |         3 |       0 |       1 |                 4 |
| Privilege Escalation |         2 |       0 |       0 |                 2 |
| Total by OS          |        28 |      15 |      17 |                60 |

Note: Latest Total Production Rules by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |        12 |       0 |       9 |                21 |
| Command and Control  |        39 |      15 |      48 |               102 |
| Credential Access    |        53 |       7 |      36 |                96 |
| Defense Evasion      |       322 |      51 |      61 |               434 |
| Discovery            |        20 |       2 |       4 |                26 |
| Execution            |        93 |      70 |     105 |               268 |
| Exfiltration         |         0 |       0 |       2 |                 2 |
| Impact               |        19 |       6 |       2 |                27 |
| Initial Access       |        62 |       1 |       2 |                65 |
| Lateral Movement     |        10 |       2 |       2 |                14 |
| Persistence          |        60 |      34 |      26 |               120 |
| Privilege Escalation |        71 |      16 |       9 |                96 |
| Total by OS          |       761 |     204 |     306 |              1271 |

### The Zen of Security Rules

We incorporate the [Zen of Security Rules](https://zenofsecurity.io/rules) into all of our rule development and planning. We strive to follow these principles to ensure practical rule design for resiliency at scale. 
