# backend/utils/log_parser.py
import json
import re

LOG_PATTERN = re.compile(
    r"(?P<timestamp>[\d\-:\s]+) user=(?P<user>\w+) ip=(?P<ip>[\d\.]+) status=(?P<status>\w+)"
)

def parse_logs(input_file, output_file):
    parsed = []

    with open(input_file, "r") as f:
        for line in f:
            match = LOG_PATTERN.search(line)
            if match:
                parsed.append(match.groupdict())

    with open(output_file, "w") as f:
        json.dump(parsed, f, indent=4)

    print("✅ Logs parsed to JSON.")

if __name__ == "__main__":
    parse_logs(
        "backend/data/raw_logs.txt",
        "backend/data/parsed_logs.json"
    )
