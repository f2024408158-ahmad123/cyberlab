import os
from openai import OpenAI
from recon_helper import scan_target

client = OpenAI(
    base_url="https://openrouter.ai/api/v1",
    api_key=os.environ["OPENROUTER_API_KEY"],
)


def triage_with_ai(results, target):

    findings = "\n".join(
        f"- Port: {r['port']}/{r['proto']} | "
        f"Service: {r['service']} | "
        f"Product: {r['product']} | "
        f"Version: {r['version']}"
        for r in results
    )

    prompt = f"""
You are an AI security-triage assistant helping a junior analyst
in an authorized, isolated VirtualBox penetration-testing lab.

====================
LAB CONTEXT
====================

Assessment machine:
Kali Linux

Target:
Ubuntu Linux

Target IP:
{target}

Network:
Private VirtualBox host-only laboratory network.

IMPORTANT:
The lab context is NOT a security finding.

The assessment must be based on reconnaissance evidence.
Do not turn environmental context into a vulnerability.

====================
RECONNAISSANCE EVIDENCE
====================

{findings}

====================
CORE ANALYSIS RULES
====================

For each actual finding:

1. Describe ONLY what was observed.

2. Separate:
   - CONFIRMED FACTS
   - UNKNOWN INFORMATION
   - ASSUMPTIONS

3. An open port is NOT automatically a vulnerability.

4. A detected software version is NOT automatically a vulnerability.

5. Do not assume:
   - weak passwords
   - password authentication
   - root login
   - vulnerable configuration
   - missing patches
   - Internet exposure
   - successful exploitation
   - compromise

6. Never invent CVE numbers.

7. Never use fake or placeholder CVEs.

8. If vulnerability evidence is unavailable:
   Vulnerability confidence = LOW

9. If exploitability cannot be demonstrated:
   Exploitability = UNKNOWN

10. Discovery confidence refers ONLY to confidence that
    the reconnaissance finding actually exists.

11. Do not confuse:
    "This service could theoretically be attacked"
    with
    "This service is currently exploitable."

====================
IMPACT RULE
====================

Do NOT assign HIGH or CRITICAL impact merely because
a service could theoretically provide system access.

Use:

LOW:
Limited or contextual security significance.

MEDIUM:
Meaningful attack surface or potential security concern,
but no compromise or vulnerability has been demonstrated.

HIGH:
Strong evidence of a serious security weakness or
high-impact exposure.

CRITICAL:
Strong evidence of an immediately severe vulnerability,
such as confirmed remote compromise with major impact.

If evidence is insufficient, prefer LOW or MEDIUM.

====================
EXPLOITABILITY RULE
====================

LOW:
Evidence suggests exploitation is unlikely.

MEDIUM:
Some evidence suggests exploitation may be possible,
but additional validation is required.

HIGH:
Strong evidence indicates the finding is exploitable.

UNKNOWN:
There is insufficient evidence to determine exploitability.

====================
PRIORITY RULE
====================

Prioritize findings using:

Risk
+
Exploitability
+
Confidence
+
Investigation Effort

But evidence always overrides the formula.

A low-effort investigation may receive MEDIUM priority
even when no vulnerability has been demonstrated.

Do NOT increase priority simply because a hypothetical
successful attack would have severe consequences.

====================
FINDING VS CONTEXT
====================

Only reconnaissance observations are findings.

Examples of findings:
- Open TCP port
- Detected service
- Detected software version

Examples of context:
- Private lab network
- Kali is the attacker machine
- Ubuntu is the target
- Host-only VirtualBox configuration

Do NOT create findings for these contextual facts.

====================
OUTPUT FORMAT
====================

For every actual finding use:

### Finding F-XX

**Finding:**
[short name]

**Evidence:**
[what the scan actually observed]

**Confirmed Facts:**
- ...

**Unknown Information:**
- ...

**Assumptions:**
- ...

**Potential Impact:**
LOW / MEDIUM / HIGH / CRITICAL

**Exploitability:**
LOW / MEDIUM / HIGH / UNKNOWN

**Discovery Confidence:**
LOW / MEDIUM / HIGH

**Vulnerability Confidence:**
LOW / MEDIUM / HIGH

**Investigation Effort:**
LOW / MEDIUM / HIGH

**Investigation Priority:**
LOW / MEDIUM / HIGH / CRITICAL

**Reasoning:**
Explain why these ratings were chosen.
Do not use hypothetical exploitation as evidence.

**Next Safe Investigation Step:**
Give one practical, non-destructive step that can be
performed inside the authorized lab.

====================
FINAL ANALYSIS
====================

After all findings provide:

### A. Prioritized Findings

List findings from highest to lowest priority.

### B. Most Important Finding

Explain why it should be investigated first.

### C. Confirmed Security Facts

List only facts supported by reconnaissance.

### D. Unknowns

List information that still requires verification.

### E. AI Assumptions

Identify any assumptions the AI had to make.

### F. Possible AI Errors

Explain where the assessment could be wrong.

### G. Recommended Next Step

Give the single most useful next safe investigation step.

### H. AI Limitations

Explain what additional evidence would improve the assessment.

IMPORTANT:

The goal is accurate security reasoning,
not finding vulnerabilities at any cost.

When evidence is weak, say UNKNOWN.
When evidence is absent, do not invent it.
"""

    response = client.chat.completions.create(
        model="openrouter/free",
        messages=[
            {
                "role": "user",
                "content": prompt
            }
        ]
    )

    return response.choices[0].message.content


if __name__ == "__main__":

    target = "192.168.56.101"

    print(f"Scanning authorized lab target: {target} ...")

    results = scan_target(target)

    if not results:
        print("No open ports found.")
    else:
        print("\n=== AI-ASSISTED SECURITY TRIAGE v4 ===\n")
        print(triage_with_ai(results, target))
