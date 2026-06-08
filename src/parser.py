import re
from datetime import datetime

pattern = re.compile(
    r"(\w+\ \d+\ \d+\:\d+\:\d+).*?(?P<user>\w+) from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) .*?port (?P<port>\d+)"
)


def read_log(log_path):
    with open(log_path) as file:
        line = file.read()
    return line


def parse_timestamp(raw_ts):
    now = datetime.now()
    raw = f"{now.year} {raw_ts}"
    formatted = datetime.strptime(raw, "%Y %b %d %H:%M:%S")
    return formatted


def parse_log(log_path):

    line = read_log(log_path)

    final_data = []

    for i in pattern.finditer(line):
        raw_ts = i.group(1)
        formatted_ts = parse_timestamp(raw_ts).strftime("%Y-%m-%d %H:%M:%S")

        log_data = {"timestamp": formatted_ts, **i.groupdict()}

        final_data.append(log_data)

    return final_data
