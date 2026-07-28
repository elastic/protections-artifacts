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
| production-rules-linux-v1 | 1.0.121 | 89c9146562df915256b54b6aa20ab4919efb01de3d03576b4298c4170260148b |
| production-rules-macos-v1 | 1.0.121 | 209cbebefdd84f25e657d935c7735de3e67a4320803b397f452f25a51d87fd6a |
| production-rules-windows-v1 | 1.0.121 | 0c4d914245406717926128b801df3b5a6a6e091d722442d4217fea30c4584a68 |

### Rules Summary per Tactic

Note: New Production Rules since last version ('1.0.121', '1.0.120') by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Defense Evasion      |         2 |       2 |       1 |                 5 |
| Execution            |         1 |       2 |       0 |                 3 |
| Persistence          |         0 |       1 |       0 |                 1 |
| Privilege Escalation |         0 |       1 |       0 |                 1 |
| Total by OS          |         3 |       6 |       1 |                10 |

Note: Latest Total Production Rules by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |        13 |       4 |      10 |                27 |
| Command and Control  |        40 |      22 |      41 |               103 |
| Credential Access    |        53 |      12 |      36 |               101 |
| Defense Evasion      |       328 |      73 |      63 |               464 |
| Discovery            |        20 |       5 |       3 |                28 |
| Execution            |        99 |      68 |     106 |               273 |
| Exfiltration         |         0 |       1 |       2 |                 3 |
| Impact               |        19 |       6 |       2 |                27 |
| Initial Access       |        65 |       4 |       5 |                74 |
| Lateral Movement     |        10 |       2 |       1 |                13 |
| Persistence          |        61 |      28 |      21 |               110 |
| Privilege Escalation |        76 |      26 |       9 |               111 |
| Total by OS          |       784 |     251 |     299 |              1334 |

### MITRE ATT&CK Coverage

#### XDR MITRE scorecard (endpoint + endpoint-scoped SIEM)

- Catalog: 61 parent techniques (Win/Linux/macOS under 8 scorecard tactics)
- Covered (union): 49/61 (80.33%) — production endpoint rules plus production SIEM rules with metadata.integration including "endpoint" and/or index matching logs-endpoint.events*/ logs-endpoint.alerts*
- Techniques — endpoint-only: 1, SIEM-only: 4, both: 44
- Rules — production endpoint: 1300, SIEM (in-scope + MITRE): 1022

#### Uncovered scorecard techniques (12 distinct parents; listed under each tactic where ATT&CK places them)

- Execution
  - T1674  Input Injection
- Persistence
  - T1668  Exclusive Control
  - T1653  Power Settings
- Defense Evasion
  - T1622  Debugger Evasion
  - T1678  Delay Execution
  - T1480  Execution Guardrails
  - T1207  Rogue Domain Controller
  - T1679  Selective Exclusion
  - T1221  Template Injection
- Credential Access
  - T1111  Multi-Factor Authentication Interception
- Impact
  - T1561  Disk Wipe
  - T1529  System Shutdown/Reboot
