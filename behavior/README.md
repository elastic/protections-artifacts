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
| production-rules-linux-v1 | 1.0.129 | 041450fc1d27d7cdd4ab39138b2fe21ad6d69b184d8ebd8d171e9fdd13733744 |
| production-rules-macos-v1 | 1.0.129 | ea2eb934c68fbc509493738427fa6eebc5b24cd978fc78633be79427b615e741 |
| production-rules-windows-v1 | 1.0.129 | a9f998ab1c39ef00c63194b36c6070eef8bd28b02ed3a49e1d47b892a54ea834 |

### Rules Summary per Tactic

Note: New Production Rules since last version ('1.0.129', '1.0.128') by OS/MITRE Tactic.

| Tactic            |   Windows |   Linux |   macOS |   Total by Tactic |
|-------------------|-----------|---------|---------|-------------------|
| Credential Access |         1 |       0 |       0 |                 1 |
| Defense Evasion   |         2 |       2 |       0 |                 4 |
| Execution         |         0 |       1 |       0 |                 1 |
| Initial Access    |         0 |       1 |       0 |                 1 |
| Persistence       |         0 |       1 |       0 |                 1 |
| Total by OS       |         3 |       5 |       0 |                 8 |

Note: Latest Total Production Rules by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |        13 |       4 |      10 |                27 |
| Command and Control  |        45 |      23 |      42 |               110 |
| Credential Access    |        58 |      16 |      38 |               112 |
| Defense Evasion      |       333 |      86 |      63 |               482 |
| Discovery            |        20 |       5 |       3 |                28 |
| Execution            |       102 |      69 |     105 |               276 |
| Exfiltration         |         0 |       1 |       2 |                 3 |
| Impact               |        19 |       6 |       2 |                27 |
| Initial Access       |        67 |       6 |       7 |                80 |
| Lateral Movement     |        10 |       2 |       1 |                13 |
| Persistence          |        61 |      29 |      21 |               111 |
| Privilege Escalation |        76 |      28 |       9 |               113 |
| Total by OS          |       804 |     275 |     303 |              1382 |

### MITRE ATT&CK Coverage

#### XDR MITRE scorecard (endpoint + endpoint-scoped SIEM)

- Catalog: 61 parent techniques (Win/Linux/macOS under 8 scorecard tactics)
- Covered (union): 49/61 (80.33%) — production endpoint rules plus production SIEM rules with metadata.integration including "endpoint" and/or index matching logs-endpoint.events*/ logs-endpoint.alerts*
- Techniques — endpoint-only: 1, SIEM-only: 4, both: 44
- Rules — production endpoint: 1340, SIEM (in-scope + MITRE): 1062

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
