# pyshell
Python Shell API 


# Example usage and testing code for PyShell
1. Create a config.json file:
```
{
    "encryption_key": "MySecureEncryptionKeyWith30Plus!",
    "host": "127.0.0.1",
    "port": 5050,
    "proc_timeout": 1800
}
```

2. Install dependencies:
```
pip install flask cryptography
```

3. Run the server:
```
python api_server.py
```

4. Test with curl or requests:

Example client code:
```python
import requests
import json
from api_server import AESCrypto

# Initialize crypto with same key (minimum 30 characters)
crypto = AESCrypto("MySecureEncryptionKeyWith30Plus!")

# Prepare request
request_data = {
    "cmd": "echo",
    "args": ["Hello, World!"]
}

# Encrypt request
encrypted_request = crypto.encrypt(json.dumps(request_data))

# Send request
response = requests.post('http://localhost:5000/execute', 
                        json={'data': encrypted_request})

# Decrypt response
if response.status_code == 200:
    encrypted_response = response.json()['data']
    decrypted_response = crypto.decrypt(encrypted_response)
    result = json.loads(decrypted_response)
    print(f"Exit code: {result['exit_code']}")
    print(f"Stdout: {result['stdout']}")
    print(f"Stderr: {result['stderr']}")
```


# Example usage and testing code for PyShellClient
Package.json example:
```
{
  "name": "shell-command-client",
  "version": "1.0.0",
  "description": "Node.js client for AES256-CTR encrypted shell command API",
  "main": "client.js",
  "dependencies": {},
  "bin": {
    "shell-client": "./client.js"
  }
}
```

Installation and Usage:
1. Add environment variable MONKSHU_HOME to point to Monkshu so libraries can be loaded.

3. Usage examples:
   
## Execute commands with default host/port (localhost:5050)
```
node client.js ls -la
node client.js echo "Hello World"
node client.js --shellscript ./test.sh ls
```

## Execute commands with custom host/port
```
node client.js --host 192.168.1.100 --port 8080 ls -la
node client.js -h api.example.com -p 443 pwd
node client.js -h api.example.com -p 443 --shellscript ./test.sh ls
```

## Use custom key file
```
node client.js --key MySecretAESKeyOfAtLeast30Characters ls -la
```

## Combined options
```
node client.js --host 10.0.0.1 --port 9000 --key MySecretAESKeyOfAtLeast30Characters echo "Hello"
node client.js --host 10.0.0.1 --port 9000 --key MySecretAESKeyOfAtLeast30Characters --shellscript ./test.sh ls
```

## Health check with custom host/port
```
node client.js --host 192.168.1.100 --port 8080 --health
```

## Interactive mode with custom host/port
```
node client.js --host api.example.com --port 443 --interactive
```

4. Programmatic usage:
Running commands
```
const { ShellCommandClient } = require('./client');

const client = new ShellCommandClient('http://api.example.com:8080', aesKey);
const result = await client.executeCommand('ls', ['-la']);
console.log(result);
```

Running shell scripts remotely
```
const { ShellCommandClient } = require('./client');

const client = new ShellCommandClient('http://api.example.com:8080', aesKey);
const result = await client.executeScript("#!/bin/bash\necho Hello\nbash -c $1", "/tmp/test.sh", ["ls"]);
console.log(result);
```
