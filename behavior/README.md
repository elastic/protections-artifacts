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
| production-rules-linux-v1 | 1.0.61 | 638716213ea23a53fed8644e6108df9cee281085ebfd1fc54d0b31dc43ef7838 |
| production-rules-macos-v1 | 1.0.61 | 2ae67600d534e61e99a91331f7524b0e69569c6f7bfe35ff2fab89465dcf7809 |
| production-rules-windows-v1 | 1.0.61 | 73d23ced6ac96a68e4525a7f73759438e2a639a9c7aa24a0c95059a6fa2833d5 |

### Rules Summary per Tactic

Note: New Production Rules since last version ('1.0.63', '1.0.62') by OS/MITRE Tactic.
| Tactic              |   Windows |   Linux |   macOS |   Total by Tactic |
|---------------------|-----------|---------|---------|-------------------|
| Collection          |         0 |       0 |       1 |                 1 |
| Command and Control |         1 |       0 |       0 |                 1 |
| Credential Access   |         0 |       0 |       1 |                 1 |
| Defense Evasion     |         2 |       0 |       0 |                 2 |
| Execution           |         1 |       0 |       2 |                 3 |
| Exfiltration        |         0 |       0 |       1 |                 1 |
| Total by OS         |         4 |       0 |       5 |                 9 |

Note: Latest Total Production Rules by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |        11 |       0 |       3 |                14 |
| Command and Control  |        31 |       3 |      25 |                59 |
| Credential Access    |        32 |       3 |      21 |                56 |
| Defense Evasion      |       222 |       9 |      36 |               267 |
| Discovery            |         4 |       0 |       3 |                 7 |
| Execution            |        56 |      10 |      54 |               120 |
| Exfiltration         |         0 |       0 |       1 |                 1 |
| Impact               |        14 |       2 |       2 |                18 |
| Initial Access       |        49 |       1 |       2 |                52 |
| Lateral Movement     |         8 |       1 |       1 |                10 |
| Persistence          |        52 |       2 |      17 |                71 |
| Privilege Escalation |        58 |       5 |       8 |                71 |
| Total by OS          |       537 |      36 |     173 |               746 |



### The Zen of Security Rules

We incorporate the [Zen of Security Rules](https://zenofsecurity.io/rules) into all of our rule development and planning. We strive to follow these principles to ensure practical rule design for resiliency at scale. 

