from collections import Counter


def count_ips(alerts):
    return Counter(match["ip"] for match in alerts)


def top_ips(alerts):
    return count_ips(alerts).most_common(3)


def detect_bruteforce(alerts, threshold=5):
    counts = count_ips(alerts)

    return {ip: count for ip, count in counts.items() if count >= threshold}
