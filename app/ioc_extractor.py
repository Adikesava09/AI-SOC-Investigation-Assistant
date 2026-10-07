import re


def extract_iocs(alert):

    ip_addresses = re.findall(
        r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        alert
    )

    domains = re.findall(
        r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b',
        alert
    )

    urls = re.findall(
        r'https?://[^\s]+',
        alert
    )

    hashes = re.findall(
        r'\b[a-fA-F0-9]{32,64}\b',
        alert
    )

    return {
        "IP Addresses": ip_addresses,
        "Domains": domains,
        "URLs": urls,
        "Hashes": hashes
    }