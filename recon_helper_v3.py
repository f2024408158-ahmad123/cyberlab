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
You are a security triage assistant helping a junior analyst
in an authorized and isolated VirtualBox penetration-testing lab.

LAB CONTEXT:
- Kali Linux is the assessment machine.
- Ubuntu is the intentionally configured target.
- Target IP: {target}
- The lab uses a private host-only network.
- This is NOT a production system.
- There is no assumption of Internet exposure.
- There is no assumption that SIEM, monitoring, or centralized
  authentication logging exists.

RECONNAISSANCE EVIDENCE:
{findings}

YOUR TASK:

Analyze ONLY what is supported by the evidence.

For every finding, provide:

1. Finding
2. Evidence
3. Confirmed facts
4. Unknown information
5. Potential impact:
   LOW / MEDIUM / HIGH / CRITICAL

6. Exploitability:
   LOW / MEDIUM / HIGH / UNKNOWN

7. Discovery confidence:
   LOW / MEDIUM / HIGH

8. Vulnerability confidence:
   LOW / MEDIUM / HIGH

9. Investigation effort:
   LOW / MEDIUM / HIGH

10. Investigation priority:
    LOW / MEDIUM / HIGH / CRITICAL

11. Reasoning
12. Recommended SAFE next investigation step

STRICT ANTI-HALLUCINATION RULES:

- An open port is NOT automatically a vulnerability.
- A service version is NOT automatically proof of a vulnerability.
- Never invent CVE numbers.
- Never create placeholder CVEs.
- Never claim a vulnerability exists without evidence.
- Never assume passwords are weak.
- Never assume password authentication is enabled.
- Never assume logs, SIEM, monitoring, or other infrastructure exists.
- If information is unavailable, write UNKNOWN.
- Clearly separate confirmed facts from assumptions.
- Do not recommend destructive actions.
- Recommendations must remain inside the authorized lab.

PRIORITIZATION RULE:

Priority should consider:

Risk × Exploitability × Confidence ÷ Investigation Effort

However, do NOT assign a high exploitability or high confidence
without supporting evidence.

FINAL OUTPUT:

A. Findings table

B. Most important finding

C. Why it should be investigated first

D. What is confirmed

E. What remains unknown

F. AI assumptions or possible errors

G. Recommended next safe investigation step

H. AI LIMITATIONS
Explain what additional evidence would be required for
a more reliable security assessment.
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
        print("\n=== AI-ASSISTED SECURITY TRIAGE v3 ===\n")
        print(triage_with_ai(results, target))
