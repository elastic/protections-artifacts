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
| production-rules-linux-v1 | 1.0.103 | b63ee683cd02b6726b1a528dee3c1b73c74d08a9d121f0e9a1c840da24d9d8e0 |
| production-rules-macos-v1 | 1.0.103 | 1d6cd7452aa58eb4bf38664a7dab7523be7cc8f372e9c5e027103877165bab57 |
| production-rules-windows-v1 | 1.0.103 | 8258bb281e3d01bf215035c105d65c69ca5d741e4a10df68879d8b87169752a3 |

### Rules Summary per Tactic

Note: New Production Rules since last version ('1.0.103', '1.0.102') by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |         0 |       0 |       1 |                 1 |
| Command and Control  |         1 |       0 |       4 |                 5 |
| Defense Evasion      |         4 |       0 |       0 |                 4 |
| Execution            |         0 |       5 |       5 |                10 |
| Exfiltration         |         0 |       0 |       1 |                 1 |
| Persistence          |         0 |       0 |       1 |                 1 |
| Privilege Escalation |         0 |       1 |       0 |                 1 |
| Total by OS          |         5 |       6 |      12 |                23 |

Note: Latest Total Production Rules by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |        11 |       0 |      10 |                21 |
| Command and Control  |        38 |      13 |      45 |                96 |
| Credential Access    |        49 |       4 |      32 |                85 |
| Defense Evasion      |       307 |      49 |      58 |               414 |
| Discovery            |        20 |       1 |       4 |                25 |
| Execution            |        92 |      62 |      99 |               253 |
| Exfiltration         |         0 |       0 |       2 |                 2 |
| Impact               |        19 |       6 |       2 |                27 |
| Initial Access       |        62 |       1 |       2 |                65 |
| Lateral Movement     |        10 |       2 |       2 |                14 |
| Persistence          |        57 |      34 |      25 |               116 |
| Privilege Escalation |        69 |      15 |       8 |                92 |
| Total by OS          |       734 |     187 |     289 |              1210 |

### The Zen of Security Rules

We incorporate the [Zen of Security Rules](https://zenofsecurity.io/rules) into all of our rule development and planning. We strive to follow these principles to ensure practical rule design for resiliency at scale. 
