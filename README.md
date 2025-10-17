# DNS exfiltration server

DNS server weaponized to exfiltrate information

## Features

- Send task for targets (client) to execute as RCE
- Receive data from task execut
- Receive data in multipart load for data exceeding the DNS FQDN size limit

## Requirements

- Python3
- Install `dnslib` python module
- Install `pycryptodome` python module

```bash
pip install dnslib
pip install pycryptodome
# OR
pip3 install dnslib
pip3 install pycryptodome
```

## Usage

Set the following constants to define the SERVER 
**NOTE:** using `53` port requires root permissions

`EXPECTED_DOMAIN` is the domain to the client should send the request

```python
SERVER_ADDRESS = '0.0.0.0'
SERVER_PORT = 5353
EXPECTED_DOMAIN = 'domain.local'
```

To run the server use:

```bash
python3 ./server.py
```

Run the client with

```bash
python3 ./client_PoC.py
```

## How it works

The server receives and processes DNS request TYPE `AAAA` on this code version but can use another TYPE.

There are two types of requests sent by the client (agent) to the server.

1. **Callback request:** Get tasks and check client <> server connection
2. **Exfiltration request:** Send data from tasks results

Each request type has its own data syntax, but both have the same request syntax, like the following:

- **Request syntax:** `<ba64_encoded_data>.<domain>`
- **Example:** `RG9uJ3QgZGVjb2RlIHRoYXQgYml0Y2gsIHRoaXMgaXMganVzdCBhIHNhbXBsZSA.domain.local`

The request follows the DNS limitations and syntax:

- Full FQDN size less than 255 characters
- Each FQDN label size is less than 63 characters.

About the client request data segment, it has the required payload with an **AES encryption** first and then is base64 encoded to avoid bad characters in URLs,
each b64 encoded string is fragmented to ensure the required syntax.

### Requests

#### Callback

These are the simplest requests; their payload only sends the `agent_id`, which is the client (agent) identifier.

**Example of a callback request in plain text:** `agent_01.domain.local`

The agent ID here is also encrypted with AES and encoded in b64, when the server receives this petition-type update,
the agent's last time of connection with date and time is updated to know if the agent is alive, and check for a pending task to execute on the client;
if there is a pending task, send the following payload in the TXT record response.

- **Syntax:** `<message_id>:<task command>`
- **Example:** `812960: cat /etc/passwd`
- **No task response:** `[NOTHING]`

**message_id** works as a transaction ID to ensure the sending of concurrent messages and assemble different parts of data for the task results, the client tries to execute the command and send the results in the exfiltration request.

Here the request and payload data are always encrypted with AES and encoded in b64.

#### Exfiltration

On this request type, the client can send the task results using the **message_id** to know and tell the server what data chunks correspond to what task execution,
because some results exceed the size permitted limits, the client encodes the result data in base 64 without encryption and divides it into chunks of 48 bytes to 
create data envelopes that permit a future assembling on the server side

The data envelope has this structure:

- **agent_id:** Client ID
- **message_id:** Transaction ID linked to the executed task
- **chunk_index:** Index to specify the position of each chunk in the assembled data
- **size:** Total size of exfiltrated data, to check when data is fully loaded
- **data:** base64 encoded data part

```json
    {
        "agent_id": AGENT_ID,
        "message_id": message_id,
        "chunk_index": idx,
        "size": total_size,
        "data": chunk
    }
```

Each data envelope is encrypted with AES and encoded with base 64; if the resultant b64 string exceeds 63 characters, it's subdivided into many labels. The chunk data is sent to the server like
this one request: `RG9uJ3QgZGVjb2RlIHRoYXQgYml0Y2gsIHRoaXMgaXMganVzdCBhIHNhbXBsZSA.domain.local`

When the server takes the incoming data, decodes and decrypts it, and sends the data envelope to the appropriate agent record and saves it in the correct message data based on the `message_id` value, the server does the same with all the received chunks until the message reaches the expected data length specified on the `size` value in the envelope.

If the size is reached, the server assembles the data chunks in a b64 string following each chunk index and decrypts it from AES, obtaining the rtaks result in plain text.

The server responds to the exfiltration request with `[NEXT]` in the TXT response records, which are also encrypted and encoded.

### Server Process

For every incoming request, check first for the `EXPECTED_DOMAIN`. If any request contains that server, ignore the request and respond with `"PONG"` in the TXT record, then, with the valid domain, the server decodes and decrypts the payload to check the request type. For callbacks, it takes the agent_id and searches the pending task to execute. In the case of an exfiltration request, it does all the processes mentioned above to record and assemble the received data.

All the requests are all answered in **TXT RECORDS** with also AES-encrypted and b64-encoded data, which is divided into chunks of 255 bytes or less to ensure TXT limits.

---

**⚠️⚠️⚠️ WARNING:** This repo is just a PoC, don't use for malicious purposes
> Don't be stupid jail is real
