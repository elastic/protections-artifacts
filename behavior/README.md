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
| production-rules-linux-v1 | 1.0.114 | afb202231e14d6a326878a3655b6d04fb8803d45ad272787d92316f0e29a9158 |
| production-rules-macos-v1 | 1.0.114 | 2396f0e4b3fef210c85f627876a46796a91e58c970ea61acd1b8d97f3f0fc0a8 |
| production-rules-windows-v1 | 1.0.114 | ab2b2ef7c58b8c5ab14dd58ea40f41d8211cb436913ea6069b0c63a5068cf5c3 |

### Rules Summary per Tactic

Note: New Production Rules since last version ('1.0.114', '1.0.113') by OS/MITRE Tactic.

| Tactic              |   Windows |   Linux |   macOS |   Total by Tactic |
|---------------------|-----------|---------|---------|-------------------|
| Command and Control |         0 |       0 |       1 |                 1 |
| Credential Access   |         0 |       0 |       1 |                 1 |
| Defense Evasion     |         1 |       3 |       2 |                 6 |
| Execution           |         1 |       0 |       1 |                 2 |
| Persistence         |         0 |       1 |       0 |                 1 |
| Total by OS         |         2 |       4 |       5 |                11 |

Note: Latest Total Production Rules by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |        12 |       0 |       8 |                20 |
| Command and Control  |        40 |      11 |      42 |                93 |
| Credential Access    |        52 |       7 |      35 |                94 |
| Defense Evasion      |       322 |      47 |      61 |               430 |
| Discovery            |        20 |       1 |       1 |                22 |
| Execution            |        96 |      58 |     105 |               259 |
| Exfiltration         |         0 |       0 |       2 |                 2 |
| Impact               |        19 |       6 |       2 |                27 |
| Initial Access       |        62 |       1 |       2 |                65 |
| Lateral Movement     |        10 |       2 |       1 |                13 |
| Persistence          |        61 |      26 |      21 |               108 |
| Privilege Escalation |        73 |      14 |       9 |                96 |
| Total by OS          |       767 |     173 |     289 |              1229 |
