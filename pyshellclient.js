/**
 * Node.js Client for AES256-CTR Encrypted Shell Command API
 * Communicates with the Python Flask Shell API using encrypted JSON
 * 
 * AI Generated - Claude then manually modified.
 * 
 * Needs Monkshu libraries - crypt and httpClient
 */

const MONKSHULIBDIR = global.CONSTANTS ? CONSTANTS.LIBDIR : process.env.MONKSHU_HOME+"/backend/server/lib";

const crypt = require(`${MONKSHULIBDIR}/crypt.js`);
global.LOG = console; global.LOG.info = _=>{};  // this quitens the HTTP client info messages
const {fetch} = require(`${MONKSHULIBDIR}/httpClient.js`);

class ShellCommandClient {
    constructor(apiUrl = 'http://localhost:5000', aesKey) {this.apiUrl = apiUrl; this.aesKey = aesKey;}

    async executeCommand(cmd, args = [], timeout) {
        try {
            // Prepare request data
            const requestData = {
                cmd: cmd,
                args: Array.isArray(args) ? args : [args]
            };

            // Encrypt request
            const encryptedRequest = crypt.encrypt(JSON.stringify(requestData), this.aesKey,
                undefined, true).toString("base64");

            // Send HTTP request
            const response = await fetch(`${this.apiUrl}/execute`, {
                method: "POST",
                headers: {'content-type': 'application/json; charset=UTF-8'},
                body: JSON.stringify({data: encryptedRequest}),
                timeout
            });
            if (response.status == 408) throw {request: encryptedRequest};
            if ((!response.ok) || (response.status != 200)) throw {response};

            // Decrypt response
            const encryptedResponse = (await response.json()).data;
            const encryptedBytes = Buffer.from(encryptedResponse, 'base64');
            const decryptedResponse = crypt.decrypt(encryptedBytes, this.aesKey);
            const result = JSON.parse(decryptedResponse);

            return result;

        } catch (error) {
            if (error.response) {
                // HTTP error response
                throw new Error(`API Error: ${error.response.status} - ${JSON.stringify(error.response.data)}`);
            } else if (error.request) {
                // Network error
                throw new Error(`Network Error: Unable to reach API at ${this.apiUrl}`);
            } else {
                // Other error
                throw new Error(`Client Error: ${error.message}`);
            }
        }
    }

    async healthCheck(timeout) {
        try {
            const response = await fetch(`${this.apiUrl}/health`, {timeout});
            if (response.status == 408) throw {response};
            if ((!response.ok) || (response.status != 200)) throw {response};
            const encryptedResponse = (await response.json()).data;
            const encryptedBytes = Buffer.from(encryptedResponse, 'base64');
            const decryptedResponse = crypt.decrypt(encryptedBytes);
            const result = JSON.parse(decryptedResponse);
            return result;
        } catch (error) {
            throw new Error(`Health check failed: ${error.message}`);
        }
    }
}

// Parse command line arguments for host and port
function parseCommandLineArgs() {
    const args = process.argv.slice(2);
    let host = 'localhost';
    let port = 5000;
    let aesKey;
    let commandArgs = [];
    
    for (let i = 0; i < args.length; i++) {
        if (args[i] === '--host' || args[i] === '-h') {
            if (i + 1 < args.length) {
                host = args[++i];
            } else {
                throw new Error('--host requires a value');
            }
        } else if (args[i] === '--port' || args[i] === '-p') {
            if (i + 1 < args.length) {
                port = parseInt(args[++i]);
                if (isNaN(port) || port < 1 || port > 65535) {
                    throw new Error('--port must be a valid port number (1-65535)');
                }
            } else {
                throw new Error('--port requires a value');
            }
        } else if (args[i] === '--key' || args[i] === '-k') {
            if (i + 1 < args.length) {
                aesKey = args[++i];
            } else {
                throw new Error('--config requires a value');
            }
        } else {
            // Remaining args are the command
            commandArgs = args.slice(i);
            break;
        }
    }
    
    const apiUrl = `http://${host}:${port}`;
    return { apiUrl, aesKey, commandArgs };
}

// CLI Interface
async function main() {
    try {
        // Parse command line arguments
        const { apiUrl, aesKey, commandArgs } = parseCommandLineArgs();
        
        if (commandArgs.length === 0) {
            console.log('Usage:');
            console.log('  node client.js [options] <command> [args...]');
            console.log('  node client.js [options] --health');
            console.log('  node client.js [options] --interactive');
            console.log('\nOptions:');
            console.log('  --host, -h <host>     API server host (default: localhost)');
            console.log('  --port, -p <port>     API server port (default: 5000)');
            console.log('  --key, -k <aes_key>   AES Key (default: default Monkshu key)');
            console.log('\nExamples:');
            console.log('  node client.js ls -la');
            console.log('  node client.js --host 192.168.1.100 --port 8080 ls -la');
            console.log('  node client.js -h api.example.com -p 443 echo "Hello World"');
            console.log('  node client.js --key "MySecret30Character"');
            console.log('  node client.js --interactive');
            process.exit(1);
        }

        // Initialize client with parsed parameters
        const client = new ShellCommandClient(apiUrl, aesKey);
        console.log(`Connecting to API at: ${apiUrl}`);

        // Handle special commands
        if (commandArgs[0] === '--health') {
            const health = await client.healthCheck();
            console.log('Health Check Result:', JSON.stringify(health, null, 2));
            return;
        }

        if (commandArgs[0] === '--interactive') {
            await interactiveMode(client);
            return;
        }

        // Execute command
        const cmd = commandArgs[0];
        const cmdArgs = commandArgs.slice(1);

        console.log(`Executing: ${cmd} ${cmdArgs.join(' ')}`);
        const result = await client.executeCommand(cmd, cmdArgs);

        // Display results
        console.log('\n--- Execution Result ---');
        console.log(`Exit Code: ${result.exit_code}`);
        
        if (result.stdout) {
            console.log('\nStdout:');
            console.log(result.stdout);
        }
        
        if (result.stderr) {
            console.log('\nStderr:');
            console.log(result.stderr);
        }

    } catch (error) {
        console.error('Error:', error.message);
        process.exit(1);
    }
}

// Interactive mode
async function interactiveMode(client) {
    const readline = require('readline');
    
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });

    console.log('Interactive Mode - Enter commands (type "exit" to quit)');
    console.log('Format: <command> [args...]');
    console.log('Example: ls -la\n');

    const askCommand = () => {
        rl.question('> ', async (input) => {
            const trimmed = input.trim();
            
            if (trimmed === 'exit' || trimmed === 'quit') {
                rl.close();
                return;
            }
            
            if (trimmed === '') {
                askCommand();
                return;
            }

            try {
                let parts = trimmed.split(' ');
                const cmd = parts[0]; parts = parts.slice(1);
                const args = [];
                const _countEndingSlashes = str => {
                    let count = 0, index = str.length-1; 
                    while (index >= 0) {if (str[index] == '\\') count++; else break; index--;}
                    return count; 
                }

                let quoteChar, argsToCombine = []; for (let part of parts) {
                    part = part.trim(); 
                    if ((part.startsWith('"') || part.startsWith("'")) && (!quoteChar)) {argsToCombine = [part.substring(1)]; quoteChar = part[0]}
                    else if ((part.endsWith('"') || part.endsWith("'")) && (quoteChar) && 
                            (quoteChar == part[part.length-1]) && 
                            (_countEndingSlashes(part.substring(0,part.length-1))%2 != 1)) {
                        argsToCombine.push(part.substring(0, part.length-1)); args.push(argsToCombine.join(' ')); 
                        quoteChar = undefined; argsToCombine = [];
                    }
                    else {if (quoteChar) argsToCombine.push(part); else args.push(part);}
                }
                if (argsToCombine.length) args.push(argsToCombine.join(' '));
                
                const result = await client.executeCommand(cmd, args);
                
                if (result.stdout) console.log(`Stdout: \n${result.stdout}`);
                if (result.stderr) console.log(`Stderr: \n${result.stderr}`);
                console.log(`\nExit Code: ${result.exit_code}`);

                console.log('');
                
            } catch (error) {
                console.error('Error:', error.message+"\n"+error.stack);
            }
            
            askCommand();
        });
    };

    askCommand();
}

// Export for use as module
module.exports = { ShellCommandClient };

// Run CLI if called directly
if (require.main === module) {
    main();
}

/*
Package.json example:
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

Installation and Usage:
1. Add environment variable MONKSHU_HOME to point to Monkshu so libraries can be loaded.

3. Usage examples:
   
   # Execute commands with default host/port (localhost:5000)
   node client.js ls -la
   node client.js echo "Hello World"
   
   # Execute commands with custom host/port
   node client.js --host 192.168.1.100 --port 8080 ls -la
   node client.js -h api.example.com -p 443 pwd
   
   # Use custom config file
   node client.js --config /path/to/config.json ls -la
   
   # Combined options
   node client.js --host 10.0.0.1 --port 9000 --config prod.json echo "Hello"
   
   # Health check with custom host/port
   node client.js --host 192.168.1.100 --port 8080 --health
   
   # Interactive mode with custom host/port
   node client.js --host api.example.com --port 443 --interactive

4. Programmatic usage:
   const { ShellCommandClient } = require('./client');
   
   const client = new ShellCommandClient('http://api.example.com:8080', aesKey);
   const result = await client.executeCommand('ls', ['-la']);
   console.log(result);
*/
