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
| production-rules-linux-v1 | 1.0.69 | 504c1c5081a69f1d5980e1b4ba620bf09f0726e9ecd44c71a180519f6bdca867 |
| production-rules-macos-v1 | 1.0.69 | c82884d61bd88a04e5f43f5af4d62e09c96776f3019fed66df05d91d9c457a95 |
| production-rules-windows-v1 | 1.0.69 | 2d6a507897bff754a98bcd34eb77c66864bd8ee843c647b75795d856d27e2e87 |

### Rules Summary per Tactic

Note: New Production Rules since last version ('1.0.69', '1.0.68') by OS/MITRE Tactic.
| Tactic         |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------|-----------|---------|---------|-------------------|
| Initial Access |         1 |       0 |       0 |                 1 |
| Total by OS    |         1 |       0 |       0 |                 1 |

Note: Latest Total Production Rules by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |        11 |       0 |       5 |                16 |
| Command and Control  |        31 |       4 |      26 |                61 |
| Credential Access    |        42 |       3 |      24 |                69 |
| Defense Evasion      |       239 |      15 |      47 |               301 |
| Discovery            |         6 |       0 |       4 |                10 |
| Execution            |        61 |      20 |      66 |               147 |
| Exfiltration         |         0 |       0 |       1 |                 1 |
| Impact               |        17 |       2 |       2 |                21 |
| Initial Access       |        50 |       2 |       2 |                54 |
| Lateral Movement     |         8 |       1 |       1 |                10 |
| Persistence          |        53 |      21 |      18 |                92 |
| Privilege Escalation |        58 |       7 |       8 |                73 |
| Total by OS          |       576 |      75 |     204 |               855 |



### The Zen of Security Rules

We incorporate the [Zen of Security Rules](https://zenofsecurity.io/rules) into all of our rule development and planning. We strive to follow these principles to ensure practical rule design for resiliency at scale. 

