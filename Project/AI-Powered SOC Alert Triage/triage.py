import re
from collections import defaultdict
from openai import OpenAI

client = OpenAI(api_key="YOUR_API_KEY")

def parse_logs(file_path):
    ip_attempts = defaultdict(int)

    with open(file_path, "r") as f:
        for line in f:
            match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
            if match and "Failed password" in line:
                ip = match.group(1)
                ip_attempts[ip] += 1

    return ip_attempts

def analyze_with_ai(ip_attempts):
    results = []

    for ip, count in ip_attempts.items():
        prompt = f"""
        IP: {ip}
        Failed Attempts: {count}

        Classify:
        - Alert Type
        - Severity (Low/Medium/High)
        - Is it True Positive or False Positive?
        - Explain briefly
        """

        response = client.chat.completions.create(
            model="gpt-4.1-mini",
            messages=[{"role": "user", "content": prompt}]
        )

        results.append(response.choices[0].message.content)

    return results

if __name__ == "__main__":
    data = parse_logs("logs/auth.log")
    output = analyze_with_ai(data)

    for result in output:
        print("\n--- ALERT ANALYSIS ---")
        print(result)
