# Annatar’s Shadow (APT-Annatar)

- Group Name: APT-Annatar (Annatar’s Shadow)
- Aliases: Lord of Gifts, Ransombearer Group
- First Seen: November 2024
- Primary Motivation: Financially Motivated Cybercrime, Ransomware
- Targeted Sectors: Technology, Finance, Critical Infrastructure
- **Tactics: Execution, Privilege Escalation, Discovery, Credential Dumping, Lateral Movement, Impact (Ransomware)**
- Tools Used: SMB, WMIC, PowerShell, WinRM, Custom Ransomware Tool
- Primary Objective: Data encryption and ransomware deployment, lateral movement across the internal network using credential dumping and remote services, escalation of privileges, and evasion through use of system services.

## Overview
Annatar’s Shadow, also known as APT-Annatar, operates under the guise of a legitimate threat actor. This group is a financially motivated cybercriminal operation focused on large-scale ransomware campaigns. Their tactics involve initially gaining access to a network through phishing or exploitation of vulnerabilities, followed by escalating privileges, moving laterally within the environment, and finally deploying their custom ransomware, `rb.exe`.

The group’s methods are calculated and highly deceptive, using remote execution tools like PsExec, and WinRM to silently maneuver through compromised systems. Once their control is established, they deploy a ransomware tool that encrypts data and demands cryptocurrency for decryption keys. The group’s stealthy, persistent presence in the network reflects Annatar’s corrupting influence on Middle-earth—disguised, but ultimately destructive.

## Tactics, Techniques, and Procedures (TTPs)

### Initial Access:

- T1071.001: Application Layer Protocol - Web Shell
Annatar’s Shadow gains initial access through a web shell or the exploitation of vulnerabilities in public-facing applications. They often use phishing or credential stuffing to establish a foothold, with their actions hidden behind a layer of deception.


## Mitigation and Detection Recommendations:
- Monitor for anomalous service creation and execution patterns, particularly with the `sc` command.
- Inspect `PowerShell` logs for suspicious commands, especially those related to `WMIC` and `PsExec`.
- Correlate credential dumping activity in network logs to detect lateral movement.
- Implement network segmentation and restrict access to sensitive directories and systems to limit lateral movement.
- Deploy endpoint detection and response (EDR) solutions to detect encryption processes and file extension changes indicative of ransomware.
- Use network monitoring to detect RDP or SMB/NetSession traffic, particularly from unauthorized systems.

## Conclusion:
Annatar’s Shadow (APT-Annatar) is a highly strategic and deceptive threat actor group that mimics the methods of Sauron’s own corrupting influence. Operating under the guise of a legitimate actor, they employ a series of well-known tools and techniques to infiltrate networks, escalate privileges, and silently move laterally before deploying their ransomware tooling. This final act of encryption locks valuable data and holds it for ransom, demanding payment in cryptocurrency. Organizations should be vigilant for the signs of Annatar’s Shadow and take proactive measures to detect and mitigate their malicious actions before they reach the destructive conclusion of their campaign.