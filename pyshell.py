#!/usr/bin/env python3

"""
AES256 Encrypted Shell Command API
Receives encrypted JSON requests to execute shell commands and returns encrypted responses.

AI Generated - Claude then manually modified.
(C) Tekmonks. All rights reserved.
"""

import os
import sys
import json
import base64
import socket
import hashlib
import logging
import tempfile
import threading
import subprocess
from io import StringIO
from concurrent import futures
from waitress import serve # type: ignore
from flask import Flask, request, jsonify # type: ignore
from cryptography.hazmat.backends import default_backend # type: ignore
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes # type: ignore

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
        self.key = md5_hash.encode('utf8')
    
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

# Global crypto instance
crypto = None
# Other globals
host = '127.0.0.1'
port = '5050'
PROC_TIMEOUT = 1800  # 30 minutes default timeout
RESPONSE_TTL = 600  # 10 minutes autodelete response entries
RESPONSES = {}

def load_config():
    """Load encryption key from config file"""
    global crypto, host, port, PROC_TIMEOUT
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
        PROC_TIMEOUT = int((len(sys.argv)>4 and sys.argv[4]) or os.getenv('PYSHELL_PROC_TIMEOUT') or config.get('proc_timeout') or PROC_TIMEOUT)
            
        crypto = AESCrypto(key)
        logger.info("Configuration loaded successfully")
        
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        raise

def decrypt_incoming(request):
    # Get encrypted data from request
    if not request.is_json:
        raise TypeError('Content-Type must be application/json')
    
    encrypted_input = request.json.get('data')
    if not encrypted_input:
        raise TypeError('Missing encrypted data field')
    
    # Decrypt input
    decrypted_input = crypto.decrypt(encrypted_input)
    input_data = json.loads(decrypted_input)
    return input_data

def execute_command(cmd, args, timeout=PROC_TIMEOUT):
    """Execute shell command safely and return result"""
    try:
        # Combine command and arguments
        full_command = [cmd] + args if isinstance(args, list) else [cmd, args]
        
        # Execute command with timeout and security measures, don't check i.e. raise exception on non-zero exit
        result = subprocess.run(full_command, capture_output=True, text=True, timeout=timeout, check=False)
        return { 'exit_code': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr }
        
    except subprocess.TimeoutExpired:
        return { 'exit_code': -1,'stdout': '', 'stderr': f'Command timed out after ${timeout} seconds' }
    except Exception as e:
        return { 'exit_code': -1, 'stdout': '', 'stderr': f'Execution error: {str(e)}' }

def execute_pycommand(cmd, args, timeout=PROC_TIMEOUT):
    def run():
        redirected_output = sys.stdout = StringIO()
        exec(cmd, args, {})
        sys.stdout = sys.__stdout__
        return {'exit_code': 0, 'stdout': redirected_output.getvalue(), 'stderr': ''}

    try:
        with futures.ThreadPoolExecutor(max_workers=1) as executor:
            return executor.submit(run).result(timeout=timeout)
    except futures.TimeoutError:
        return {'exit_code': -1, 'stdout': '', 'stderr': f'Execution timed out after {timeout}s'}
    except Exception as e:
        return {'exit_code': -1, 'stdout': '', 'stderr': f'Execution error: {str(e)}'}

@app.route('/execute', methods=['POST'])
def execute_endpoint():
    """Main API endpoint for encrypted command execution"""
    try:
        input_data = decrypt_incoming(request)

        # if we already have a cached response send it, no need to do anything else as the task is already running
        if input_data.get("request_id") and RESPONSES.get(input_data.get("request_id"), {}).get("response"):  
            request_id = input_data.get("request_id")
            encrypted_response = RESPONSES[request_id]["response"]
            decrypted_response = json.loads(crypto.decrypt(encrypted_response)) 
            if not decrypted_response.get("_pyshell_status") == "waiting": RESPONSES.pop(request_id, None)
            return jsonify({'data': encrypted_response})
        
        def executeCmd(request_id, remote_addr):
            # Validate input format
            if 'cmd' not in input_data and 'pycmd' not in input_data:
                return jsonify({'error': 'Missing cmd or pycmd parameter'}), 400
            
            cmd_type = 'oscmd' if 'cmd' in input_data else 'pycmd'
            cmd = input_data.get('cmd') or input_data.get('pycmd')
            args = input_data.get('args', [] if cmd_type == 'oscmd' else {})
            timeout = input_data.get('timeout', PROC_TIMEOUT)

            # Execute command
            logger.info(f"Executing: {remote_addr} -> {cmd} {args}")
            result = execute_command(cmd, args, timeout) if cmd_type == 'oscmd' else execute_pycommand(cmd, args, timeout)
            
            # Encrypt and store response
            response_json = json.dumps(result)
            encrypted_response = crypto.encrypt(response_json)
            logger.info(f"Execution result of command ${cmd_type}: {cmd} is {response_json}")

            # save the response for about 10 minutes or till RESPONSE_TTL
            if request_id:  
                RESPONSES[request_id] = {"response": encrypted_response}
                threading.Timer(RESPONSE_TTL, lambda request_id=request_id: RESPONSES.pop(request_id, None)).start()
            else: return encrypted_response

        if input_data.get("request_id"):
            request_id = input_data.get("request_id")
            # execute the command but don't wait
            threading.Thread(target=executeCmd, args=(request_id, request.remote_addr), daemon=True).start()  # run as a seperate thread
            encrypted_response = crypto.encrypt('{"_pyshell_status": "waiting"}');
            RESPONSES[request_id] = {"response": encrypted_response}
            return jsonify({'data': encrypted_response})
        else:
            # await the command to return the result
            encrypted_response = executeCmd(None, request.remote_addr)  # this is same as await executeCmd()
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
        input_data = decrypt_incoming(request)

        # if we already have a cached response send it, no need to do anything else as the task is already running
        if input_data.get("request_id") and RESPONSES.get(input_data.get("request_id"), {}).get("response"):  
            request_id = input_data.get("request_id")
            encrypted_response = RESPONSES[request_id]["response"]
            decrypted_response = json.loads(crypto.decrypt(encrypted_response))
            if not decrypted_response.get("_pyshell_status") == "waiting": RESPONSES.pop(request_id, None)
            return jsonify({'data': encrypted_response})

        def executeShellScript(request_id, remote_addr):
            # Validate input format
            if 'script' not in input_data:
                return jsonify({'error': 'Missing script parameter'}), 400
            if 'scriptfile_path' not in input_data:
                return jsonify({'error': 'Missing script parameter'}), 400
            
            script = input_data['script']
            args = input_data.get('args', [])
            cmd_shell = input_data.get('shell', "/bin/bash")
            timeout = input_data.get('timeout', PROC_TIMEOUT)
            scriptfile_path = input_data['scriptfile_path']
            scriptfile_extension = os.path.splitext(scriptfile_path)[1]
            tmp_scriptfile_path = tempfile.NamedTemporaryFile(suffix=scriptfile_extension).name

            fileout = open(tmp_scriptfile_path, "w")
            fileout.write(script)
            fileout.close()
            
            # Execute command
            logger.info(f"Executing script: {remote_addr} -> {cmd_shell} {scriptfile_path} {args}")
            result = execute_command(cmd_shell, [tmp_scriptfile_path]+args, timeout)

            try: os.remove(tmp_scriptfile_path)
            except Exception as e: logger.warning(f"Unable to remove temporary file {tmp_scriptfile_path}")
            
            # Encrypt response
            response_json = json.dumps(result)
            logger.info(f"Execution result of shellscript {scriptfile_path} is {result}")
            encrypted_response = crypto.encrypt(response_json)

            # save the response for about 10 minutes or till RESPONSE_TTL
            if request_id:  
                RESPONSES[request_id] = {"response": encrypted_response}
                threading.Timer(RESPONSE_TTL, lambda request_id=request_id: RESPONSES.pop(request_id, None)).start()
            else: return encrypted_response
        
        if input_data.get("request_id"):
            request_id = input_data.get("request_id")
            # execute the script but don't wait
            threading.Thread(target=executeShellScript, args=(request_id, request.remote_addr), daemon=True).start()
            encrypted_response = crypto.encrypt('{"_pyshell_status": "waiting"}');
            RESPONSES[request_id] = {"response": encrypted_response}
            return jsonify({'data': encrypted_response})
        else:
            # run the script to return the result
            encrypted_response = executeShellScript(None, request.remote_addr)
            return jsonify({'data': encrypted_response})
        
    except json.JSONDecodeError:
        return jsonify({'error': 'Invalid JSON in decrypted data'}), 400
    except Exception as e:
        logger.error(f"Request processing error: {e}")
        return jsonify({'error': 'Pyshell Internal Server Error'}), 500

@app.route('/health', methods=['POST'])
def health_check():
    """Health check endpoint"""
    input_data = decrypt_incoming(request)
    
    # Validate input format
    if 'health' not in input_data:
        return jsonify({'error': 'Missing health parameter'}), 400
    response_json = json.dumps({'status': 'healthy', 'crypto_initialized': crypto is not None, 
                                'user': os.getenv('USER') or os.getenv('USERNAME'), 
                                'hostname': socket.gethostname()})
    encrypted_response = crypto.encrypt(response_json)
    return jsonify({'data': encrypted_response})

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': f'Endpoint not found {error}'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': f'Internal server error {error}'}), 500

if __name__ == '__main__':
    # Load configuration on startup
    try:
        load_config()
    except Exception as e:
        print('\nUsage:   pyshell.py [AES Key] [Host to listen on] [Port to listen on] [Process Timeout]')
        print('Example: pyshell.py "My_Minimum_30_Character_AES_Key" 0.0.0.0 5050')
        print('\nHelp')
        print('----')
        print('Configuration file config.json with keys host, port, encryption_key and proc_timeout in the same folder')
        print('or the environment variable PYSHELL_CONFIG_FILE pointing to its path.')
        print('\nEnvironment variables PYSHELL_CRYPT_KEY, PYSHELL_HOST PYSHELL_PORT and PYSHELL_PROC_TIMEOUT otherwise.')
        print('\nOrder of priorities is command line argument > environment variable > configuration file.')
        sys.exit(1)
    
    # Run the Flask app
    logger.info(f"Starting on {host}:{port} proctimeout {PROC_TIMEOUT} sec")
    serve(app, host=host, port=port, ipv6=True)