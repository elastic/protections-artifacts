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
| production-rules-linux-v1 | 1.0.98 | 61201a9b1e55c074808a789f2b56e9589691ab1bb01129f579ad0dd7efdb4f21 |
| production-rules-macos-v1 | 1.0.98 | 296fc8a15ebca35e8c685169b639416a61f247e2fd03bf4e8350ae3096388c49 |
| production-rules-windows-v1 | 1.0.98 | 59e3536e3bde9049d41515da1d653da24a37421fb72d15cf9d97d06397daa022 |

### Rules Summary per Tactic

Note: New Production Rules since last version ('1.0.98', '1.0.97') by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |         2 |       0 |       0 |                 2 |
| Command and Control  |         3 |       0 |       1 |                 4 |
| Defense Evasion      |        14 |       1 |       0 |                15 |
| Execution            |         0 |       2 |       1 |                 3 |
| Initial Access       |         3 |       0 |       0 |                 3 |
| Persistence          |         1 |       0 |       0 |                 1 |
| Privilege Escalation |         1 |       0 |       0 |                 1 |
| Total by OS          |        24 |       3 |       2 |                29 |

Note: Latest Total Production Rules by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |        11 |       0 |       9 |                20 |
| Command and Control  |        37 |      14 |      39 |                90 |
| Credential Access    |        46 |       4 |      30 |                80 |
| Defense Evasion      |       294 |      51 |      57 |               402 |
| Discovery            |         7 |       1 |       4 |                12 |
| Execution            |        88 |      55 |      89 |               232 |
| Exfiltration         |         0 |       0 |       1 |                 1 |
| Impact               |        18 |       6 |       2 |                26 |
| Initial Access       |        59 |       1 |       2 |                62 |
| Lateral Movement     |        10 |       2 |       2 |                14 |
| Persistence          |        57 |      34 |      25 |               116 |
| Privilege Escalation |        68 |      13 |       8 |                89 |
| Total by OS          |       695 |     181 |     268 |              1144 |

### The Zen of Security Rules

We incorporate the [Zen of Security Rules](https://zenofsecurity.io/rules) into all of our rule development and planning. We strive to follow these principles to ensure practical rule design for resiliency at scale. 
