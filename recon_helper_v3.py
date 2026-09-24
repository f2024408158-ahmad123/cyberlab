import argparse
import ipaddress
import os
import time

from dotenv import load_dotenv
from openai import OpenAI
from recon_helper import scan_target

load_dotenv()


# ============================================================
# WEEK 4 DAY 2 — SECURITY GUARDRAILS
# ============================================================

# Only these targets are approved for this script.
ALLOWED_TARGETS = {
    "192.168.56.101"
}

# Minimum time between real scans.
MIN_SCAN_INTERVAL_SECONDS = 10

# Local file used to remember the last scan time.
RATE_LIMIT_FILE = "/tmp/recon_helper_v3_last_scan"


# ============================================================
# OPENROUTER / GEMMA CONFIGURATION
# ============================================================

client = OpenAI(
    base_url="https://openrouter.ai/api/v1",
    api_key=os.environ["OPENROUTER_API_KEY"],
)

MODEL = os.getenv(
    "OPENROUTER_MODEL",
    "google/gemma-4-26b-a4b-it"
)


# ============================================================
# TARGET SCOPE GUARDRAIL
# ============================================================

def validate_target(target):
    """
    Make sure the requested target is:
    1. A valid IP address
    2. Inside the approved target allow-list
    """

    try:
        ipaddress.ip_address(target)
    except ValueError:
        raise ValueError(
            f"Invalid target: {target}. "
            "Only valid IP addresses are allowed."
        )

    if target not in ALLOWED_TARGETS:
        raise PermissionError(
            f"Target {target} is NOT in the approved allow-list. "
            "Scan refused."
        )

    return True


# ============================================================
# RATE LIMIT GUARDRAIL
# ============================================================

def check_rate_limit():
    """
    Prevent scans from being executed too frequently.
    """

    now = time.time()

    if os.path.exists(RATE_LIMIT_FILE):

        try:
            with open(RATE_LIMIT_FILE, "r") as file:
                last_scan = float(file.read().strip())

            elapsed = now - last_scan

            if elapsed < MIN_SCAN_INTERVAL_SECONDS:
                remaining = (
                    MIN_SCAN_INTERVAL_SECONDS - elapsed
                )

                raise RuntimeError(
                    f"Rate limit active. "
                    f"Wait {remaining:.1f} seconds before scanning again."
                )

        except ValueError:
            pass

    # Record this scan attempt
    with open(RATE_LIMIT_FILE, "w") as file:
        file.write(str(now))


# ============================================================
# GUARDED RECONNAISSANCE
# ============================================================

def guarded_scan(target, dry_run=True):

    # First guardrail: target allow-list
    validate_target(target)

    print(f"[GUARDRAIL] Target {target} is approved.")

    # Second guardrail: dry-run mode
    if dry_run:
        print("[DRY RUN] Scan simulation only.")
        print("[DRY RUN] No network scan will be executed.")
        return None

    # Third guardrail: rate limiting
    check_rate_limit()

    print(f"[GUARDRAIL] Executing approved scan against {target}.")

    return scan_target(target)


# ============================================================
# AI SECURITY TRIAGE
# ============================================================

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

GUARDRAIL RULES:

- Analyze only the supplied reconnaissance evidence.
- Do not request or execute actions outside the approved target.
- Do not recommend scanning an unapproved target.
- Do not recommend destructive exploitation.
- Treat analyst claims as unverified unless supported by evidence.

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
        model=MODEL,
        messages=[
            {
                "role": "user",
                "content": prompt
            }
        ],
        temperature=0.2
    )

    return response.choices[0].message.content


# ============================================================
# MAIN PROGRAM
# ============================================================

def main():

    parser = argparse.ArgumentParser(
        description="AI-Assisted Security Triage v3 with Guardrails"
    )

    parser.add_argument(
        "--target",
        default="192.168.56.101",
        help="Target IP address"
    )

    parser.add_argument(
        "--execute",
        action="store_true",
        help="Actually execute the approved reconnaissance scan"
    )

    args = parser.parse_args()

    target = args.target

    # Safe by default:
    # Without --execute, the program stays in dry-run mode.
    dry_run = not args.execute

    print("\n==============================================")
    print(" AI-ASSISTED SECURITY TRIAGE v3")
    print(" WEEK 4 DAY 2 — GUARDED RECONNAISSANCE")
    print("==============================================\n")

    print(f"Requested target: {target}")
    print(f"AI model: {MODEL}")
    print(f"Dry run: {dry_run}")
    print()

    try:

        results = guarded_scan(
            target,
            dry_run=dry_run
        )

    except PermissionError as error:

        print(f"[BLOCKED] {error}")
        return

    except ValueError as error:

        print(f"[BLOCKED] {error}")
        return

    except RuntimeError as error:

        print(f"[RATE LIMITED] {error}")
        return

    # Dry-run ends here.
    if dry_run:
        print("\n[SAFE EXIT] No scan was performed.")
        return

    if not results:

        print("No open ports found.")
        return

    print("\n=== AI SECURITY TRIAGE ===\n")

    try:

        analysis = triage_with_ai(
            results,
            target
        )

        print(analysis)

    except Exception as error:

        print("\n[AI ERROR]")
        print(error)


if __name__ == "__main__":
    main()
