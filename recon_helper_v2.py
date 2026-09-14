import os
from openai import OpenAI
from recon_helper import scan_target  # reuses your Day 3 function

client = OpenAI(
    base_url="https://openrouter.ai/api/v1",
    api_key=os.environ["OPENROUTER_API_KEY"],
)

def summarize_with_ai(results, target):
    findings = "\n".join(
        f"{r['port']}/{r['proto']} {r['service']} {r['product']} {r['version']}"
        for r in results
    )
    prompt = f"""You are assisting a junior security analyst in an authorized lab.
Target: {target}
Nmap findings:
{findings}

1. Summarize these findings in plain English for a non-technical stakeholder.
2. Give a prioritized list of what to investigate first, with brief reasoning."""

    response = client.chat.completions.create(
        model="openrouter/free",
        messages=[{"role": "user", "content": prompt}]
    )
    return response.choices[0].message.content


if __name__ == "__main__":
    target = "192.168.56.101"
    results = scan_target(target)
    print(summarize_with_ai(results, target))
