#!/usr/bin/env python3
"""
AES256 Encrypted Shell Command API
Receives encrypted JSON requests to execute shell commands and returns encrypted responses.

AI Generated - Claude then manually modified.
"""

import json
import subprocess
import base64
import hashlib
from flask import Flask, request, jsonify
from waitress import serve
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AESCrypto:
    def __init__(self, key_string):
        """Initialize with a minimum 30-character key"""
        if len(key_string) < 30:
            raise ValueError("Key must be at least 30 characters")
        
        # Use MD5 with UTF-8 encoding, convert digest to hex and uppercase
        md5_hash = hashlib.md5(key_string.encode('utf-8')).hexdigest().upper()
        # Use the hex string as the key (32 bytes for AES-256)
        self.key = md5_hash.encode('ascii')
    
    def encrypt(self, plaintext):
        """Encrypt plaintext string and return base64 encoded result"""
        try:
            # Generate random nonce for CTR mode
            nonce = os.urandom(16)
            
            # Create cipher
            cipher = Cipher(algorithms.AES(self.key), modes.CTR(nonce), backend=default_backend())
            encryptor = cipher.encryptor()
            
            # Encrypt (no padding needed for CTR mode)
            ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
            
            # Combine ciphertext and nonce (nonce at end), then base64 encode
            encrypted_data = ciphertext + nonce
            return base64.b64encode(encrypted_data).decode('utf-8')
            
        except Exception as e:
            logger.error(f"Encryption error: {e}")
            raise
    
    def decrypt(self, encrypted_data):
        """Decrypt base64 encoded encrypted data and return plaintext string"""
        try:
            # Decode base64
            encrypted_bytes = base64.b64decode(encrypted_data.encode('utf-8'))
            
            # Extract ciphertext and nonce (nonce is last 16 bytes)
            ciphertext = encrypted_bytes[:-16]
            nonce = encrypted_bytes[-16:]
            
            # Create cipher
            cipher = Cipher(algorithms.AES(self.key), modes.CTR(nonce), backend=default_backend())
            decryptor = cipher.decryptor()
            
            # Decrypt (no padding removal needed for CTR mode)
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            return plaintext.decode('utf-8')
            
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            raise
    
    def _pad(self, data):
        """Add PKCS7 padding - Not used in CTR mode"""
        padding_length = 16 - (len(data) % 16)
        padding = bytes([padding_length] * padding_length)
        return data + padding
    
    def _unpad(self, data):
        """Remove PKCS7 padding - Not used in CTR mode"""
        padding_length = data[-1]
        return data[:-padding_length]

# Global crypto instance
crypto = None
# Other globals
host = '127.0.0.1'
port = '5000'
proctimeout = 1800  # 30 minutes default timeout

def load_config():
    """Load encryption key from config file"""
    global crypto, host, port, proctimeout
    try:
        try:
            config_file = os.getenv('PYSHELL_CONFIG_FILE', 'config.json')
            with open(config_file, 'r') as f:
                config = json.load(f)
        except Exception as e:
            config = {}

        key = os.getenv('PYSHELL_CRYPT_KEY', config.get('encryption_key'))
        if not key:
            raise ValueError("encryption_key not found in config file")
        host_modified = os.getenv('PYSHELL_HOST', config.get('host'))
        port_modified = os.getenv('PYSHELL_PORT', config.get('port'))
        timeout_modified = int(os.getenv('PYSHELL_PROC_TIMEOUT', config.get('proc_timeout')))
        host = host_modified if host_modified is not None else '127.0.0.1'
        port = port_modified if port_modified is not None else '5000'
        proctimeout = timeout_modified or proctimeout
            
        crypto = AESCrypto(key)
        logger.info("Configuration loaded successfully")
        
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        raise

def execute_command(cmd, args):
    """Execute shell command safely and return result"""
    try:
        # Combine command and arguments
        full_command = [cmd] + args if isinstance(args, list) else [cmd, args]
        
        # Execute command with timeout and security measures
        result = subprocess.run(
            full_command,
            capture_output=True,
            text=True,
            timeout=proctimeout, 
            check=False  # Don't raise exception on non-zero exit
        )
        
        return {
            'exit_code': result.returncode,
            'stdout': result.stdout,
            'stderr': result.stderr
        }
        
    except subprocess.TimeoutExpired:
        return {
            'exit_code': -1,
            'stdout': '',
            'stderr': 'Command timed out after 30 seconds'
        }
    except Exception as e:
        return {
            'exit_code': -1,
            'stdout': '',
            'stderr': f'Execution error: {str(e)}'
        }

@app.route('/execute', methods=['POST'])
def execute_endpoint():
    """Main API endpoint for encrypted command execution"""
    try:
        # Get encrypted data from request
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400
        
        encrypted_input = request.json.get('data')
        if not encrypted_input:
            return jsonify({'error': 'Missing encrypted data field'}), 400
        
        # Decrypt input
        decrypted_input = crypto.decrypt(encrypted_input)
        input_data = json.loads(decrypted_input)
        
        # Validate input format
        if 'cmd' not in input_data:
            return jsonify({'error': 'Missing cmd parameter'}), 400
        
        cmd = input_data['cmd']
        args = input_data.get('args', [])
        
        # Execute command
        logger.info(f"Executing: {request.remote_addr} -> {cmd} {args}")
        result = execute_command(cmd, args)
        
        # Encrypt response
        response_json = json.dumps(result)
        encrypted_response = crypto.encrypt(response_json)
        
        return jsonify({'data': encrypted_response})
        
    except json.JSONDecodeError:
        return jsonify({'error': 'Invalid JSON in decrypted data'}), 400
    except Exception as e:
        logger.error(f"Request processing error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    response_json = json.dumps({'status': 'healthy', 'crypto_initialized': crypto is not None})
    encrypted_response = crypto.encrypt(response_json)
    return jsonify({'data': encrypted_response})

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    # Load configuration on startup
    load_config()
    
    # Run the Flask app
    serve(app, host=host, port=port, ipv6=True)

# Example usage and testing code:
"""
1. Create a config.json file:
{
    "encryption_key": "MySecureEncryptionKeyWith30Plus!",
    "host": "127.0.0.1",
    "port": 5050,
    "proc_timeout": 1800
}

2. Install dependencies:
pip install flask cryptography

3. Run the server:
python api_server.py

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
"""
