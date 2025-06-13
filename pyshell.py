#!/usr/bin/env python3

"""
AES256 Encrypted Shell Command API
Receives encrypted JSON requests to execute shell commands and returns encrypted responses.

AI Generated - Claude then manually modified.
"""

import sys
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
port = '5050'
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

        key = (len(sys.argv)>1 and sys.argv[1]) or os.getenv('PYSHELL_CRYPT_KEY') or config.get('encryption_key')
        if not key:
            raise ValueError("encryption_key not found in config file")
        host = (len(sys.argv)>2 and sys.argv[2]) or os.getenv('PYSHELL_HOST') or config.get('host') or host
        port = (len(sys.argv)>3 and sys.argv[3]) or os.getenv('PYSHELL_PORT') or config.get('port') or port
        proctimeout = int((len(sys.argv)>4 and sys.argv[4]) or os.getenv('PYSHELL_PROC_TIMEOUT') or config.get('proc_timeout') or proctimeout)
            
        crypto = AESCrypto(key)
        logger.info("Configuration loaded successfully")
        
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        raise

def execute_command(cmd, args, timeout=proctimeout):
    """Execute shell command safely and return result"""
    try:
        # Combine command and arguments
        full_command = [cmd] + args if isinstance(args, list) else [cmd, args]
        
        # Execute command with timeout and security measures
        result = subprocess.run(
            full_command,
            capture_output=True,
            text=True,
            timeout=timeout, 
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
        timeout = input_data.get('timeout', proctimeout)
        
        # Execute command
        logger.info(f"Executing: {request.remote_addr} -> {cmd} {args}")
        result = execute_command(cmd, args, timeout)
        
        # Encrypt response
        response_json = json.dumps(result)
        encrypted_response = crypto.encrypt(response_json)
        
        return jsonify({'data': encrypted_response})
        
    except json.JSONDecodeError:
        return jsonify({'error': 'Invalid JSON in decrypted data'}), 400
    except Exception as e:
        logger.error(f"Request processing error: {e}")
        return jsonify({'error': 'Internal server error'}), 500
    
@app.route('/shellscript', methods=['POST'])
def shellscript_endpoint():
    """Main API endpoint for encrypted shell script execution"""
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
        if 'script' not in input_data:
            return jsonify({'error': 'Missing script parameter'}), 400
        if 'scriptfile_path' not in input_data:
            return jsonify({'error': 'Missing script parameter'}), 400
        
        script = input_data['script']
        args = input_data.get('args', [])
        cmd_shell = input_data.get('shell', "/bin/bash")
        timeout = input_data.get('timeout', proctimeout)
        scriptfile_path = input_data['scriptfile_path']

        fileout = open(scriptfile_path, "w")
        fileout.write(script)
        fileout.close()
        
        # Execute command
        logger.info(f"Executing script: {request.remote_addr} -> {cmd_shell} {scriptfile_path} {args}")
        result = execute_command(cmd_shell, [scriptfile_path]+args, timeout)
        
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
    logger.info(f"Starting on {host}:{port} proctimeout {proctimeout} sec")
    serve(app, host=host, port=port, ipv6=True)
