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
| production-rules-linux-v1 | 1.0.73 | 9196f0c9c85bdd903a72669af99321f3a9929aaae7592d47e8feaf845f343beb |
| production-rules-macos-v1 | 1.0.73 | 250e43c88e27be40ee6dd399c9987b06df4fba8deb83d45f646cab0ef2abbc39 |
| production-rules-windows-v1 | 1.0.73 | e6e3a54a2fcdd6fe13dad732e3919471146de80d0c03a82724376a98d7141f38 |

### Rules Summary per Tactic

Note: New Production Rules since last version ('1.0.73', '1.0.72') by OS/MITRE Tactic.
| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Defense Evasion      |         1 |       0 |       0 |                 1 |
| Discovery            |         1 |       0 |       0 |                 1 |
| Impact               |         1 |       0 |       0 |                 1 |
| Persistence          |         1 |       0 |       0 |                 1 |
| Privilege Escalation |         1 |       0 |       0 |                 1 |
| Total by OS          |         5 |       0 |       0 |                 5 |

Note: Latest Total Production Rules by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |        11 |       0 |       5 |                16 |
| Command and Control  |        31 |       7 |      27 |                65 |
| Credential Access    |        42 |       3 |      24 |                69 |
| Defense Evasion      |       251 |      24 |      48 |               323 |
| Discovery            |         8 |       1 |       4 |                13 |
| Execution            |        62 |      22 |      70 |               154 |
| Exfiltration         |         0 |       0 |       1 |                 1 |
| Impact               |        18 |       2 |       2 |                22 |
| Initial Access       |        52 |       2 |       2 |                56 |
| Lateral Movement     |         8 |       1 |       1 |                10 |
| Persistence          |        55 |      24 |      19 |                98 |
| Privilege Escalation |        60 |       8 |       8 |                76 |
| Total by OS          |       598 |      94 |     211 |               903 |



### The Zen of Security Rules

We incorporate the [Zen of Security Rules](https://zenofsecurity.io/rules) into all of our rule development and planning. We strive to follow these principles to ensure practical rule design for resiliency at scale. 

