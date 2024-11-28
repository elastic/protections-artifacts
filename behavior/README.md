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
| production-rules-linux-v1 | 1.0.77 | 205563a62accf42c00a4e86cd183182e73d6212b3aee4417b28a07fcc7d72014 |
| production-rules-macos-v1 | 1.0.77 | bc7293909d278ecc26759d38a95c7854f6b0544d8693838d8d439bba2272469f |
| production-rules-windows-v1 | 1.0.77 | e916cd07938fd05e1ac4543b5cdba016344ed18e81c1fb95b80b592765898dae |

### Rules Summary per Tactic

Note: New Production Rules since last version ('1.0.77', '1.0.76') by OS/MITRE Tactic.
| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Defense Evasion      |         3 |       0 |       0 |                 3 |
| Initial Access       |         1 |       0 |       0 |                 1 |
| Privilege Escalation |         1 |       0 |       0 |                 1 |
| Total by OS          |         5 |       0 |       0 |                 5 |

Note: Latest Total Production Rules by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |        11 |       0 |       6 |                17 |
| Command and Control  |        32 |      11 |      27 |                70 |
| Credential Access    |        44 |       4 |      24 |                72 |
| Defense Evasion      |       258 |      42 |      44 |               344 |
| Discovery            |         8 |       1 |       4 |                13 |
| Execution            |        64 |      35 |      71 |               170 |
| Exfiltration         |         0 |       0 |       1 |                 1 |
| Impact               |        18 |       4 |       2 |                24 |
| Initial Access       |        54 |       2 |       2 |                58 |
| Lateral Movement     |         8 |       1 |       1 |                10 |
| Persistence          |        56 |      29 |      17 |               102 |
| Privilege Escalation |        61 |       8 |       8 |                77 |
| Total by OS          |       614 |     137 |     207 |               958 |


### The Zen of Security Rules

We incorporate the [Zen of Security Rules](https://zenofsecurity.io/rules) into all of our rule development and planning. We strive to follow these principles to ensure practical rule design for resiliency at scale. 

