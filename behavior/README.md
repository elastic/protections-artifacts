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
| production-rules-linux-v1 | 1.0.120 | d6b221f18f376f000e1e378dc828cfbf81f79f2b29e5196199da17a54e4b34de |
| production-rules-macos-v1 | 1.0.120 | ee9f7ab9cf4d96d675ef89db6e1ab2a95fabe6908e003e174b82a6d3fcd895ce |
| production-rules-windows-v1 | 1.0.120 | 5dd6c5ccc0326f0ddeae9bf0caa57736628ee7386c5789a4fe587d73124a54e9 |

### Rules Summary per Tactic

Note: New Production Rules since last version ('1.0.120', '1.0.119') by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |         0 |       1 |       0 |                 1 |
| Command and Control  |         0 |       2 |       0 |                 2 |
| Credential Access    |         0 |       2 |       0 |                 2 |
| Defense Evasion      |         1 |       8 |       0 |                 9 |
| Discovery            |         0 |       1 |       0 |                 1 |
| Execution            |         0 |       3 |       0 |                 3 |
| Initial Access       |         1 |       1 |       2 |                 4 |
| Persistence          |         0 |       5 |       0 |                 5 |
| Privilege Escalation |         0 |       5 |       0 |                 5 |
| Total by OS          |         2 |      28 |       2 |                32 |

Note: Latest Total Production Rules by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |        13 |       4 |      10 |                27 |
| Command and Control  |        40 |      22 |      41 |               103 |
| Credential Access    |        53 |      12 |      36 |               101 |
| Defense Evasion      |       326 |      71 |      62 |               459 |
| Discovery            |        20 |       5 |       3 |                28 |
| Execution            |        98 |      66 |     106 |               270 |
| Exfiltration         |         0 |       1 |       2 |                 3 |
| Impact               |        19 |       6 |       2 |                27 |
| Initial Access       |        65 |       4 |       5 |                74 |
| Lateral Movement     |        10 |       2 |       1 |                13 |
| Persistence          |        61 |      28 |      21 |               110 |
| Privilege Escalation |        76 |      25 |       9 |               110 |
| Total by OS          |       781 |     246 |     298 |              1325 |

### MITRE ATT&CK Coverage

#### XDR MITRE scorecard (endpoint + endpoint-scoped SIEM)

- Catalog: 61 parent techniques (Win/Linux/macOS under 8 scorecard tactics)
- Covered (union): 49/61 (80.33%) — production endpoint rules plus production SIEM rules with metadata.integration including "endpoint" and/or index matching logs-endpoint.events*/ logs-endpoint.alerts*
- Techniques — endpoint-only: 1, SIEM-only: 4, both: 44
- Rules — production endpoint: 1293, SIEM (in-scope + MITRE): 1081

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
