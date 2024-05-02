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
| production-rules-linux-v1 | 1.0.60 | c68a70ef2f47b692612abdfbd611d388fc73709f7689d278eb256a8f114854fc |
| production-rules-macos-v1 | 1.0.60 | e68d7bcdab67ec4cb02199f2dc30fbb3de046d439eb84021ccde11c5c04e82da |
| production-rules-windows-v1 | 1.0.60 | 5b661e581944131d1117697f4bf17378c56142b9e4dacfe85a0d8e7910dea473 |

### Rules Summary per Tactic

Note: New Production Rules since last version ('1.0.60', '1.0.59') by OS/MITRE Tactic.
| Tactic            |   Windows |   Linux |   macOS |   Total by Tactic |
|-------------------|-----------|---------|---------|-------------------|
| Credential Access |         1 |       0 |       0 |                 1 |
| Defense Evasion   |         1 |       0 |       0 |                 1 |
| Initial Access    |         1 |       0 |       0 |                 1 |
| Total by OS       |         3 |       0 |       0 |                 3 |

Note: Latest Total Production Rules by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |        11 |       0 |       2 |                13 |
| Command and Control  |        27 |       3 |      26 |                56 |
| Credential Access    |        38 |       3 |      20 |                61 |
| Defense Evasion      |       217 |       9 |      39 |               265 |
| Discovery            |         4 |       0 |       3 |                 7 |
| Execution            |        55 |      10 |      49 |               114 |
| Exfiltration         |         0 |       0 |       1 |                 1 |
| Impact               |        14 |       2 |       2 |                18 |
| Initial Access       |        49 |       1 |       2 |                52 |
| Lateral Movement     |         8 |       1 |       1 |                10 |
| Persistence          |        52 |       2 |      17 |                71 |
| Privilege Escalation |        57 |       5 |       8 |                70 |
| Total by OS          |       532 |      36 |     170 |               738 |




### The Zen of Security Rules

We incorporate the [Zen of Security Rules](https://zenofsecurity.io/rules) into all of our rule development and planning. We strive to follow these principles to ensure practical rule design for resiliency at scale. 

