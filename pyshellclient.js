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
const {fetch} = require(`${MONKSHULIBDIR}/httpClient.js`);

class ShellCommandClient {
    constructor(apiUrl = 'http://localhost:5000') {this.apiUrl = apiUrl;}

    async executeCommand(cmd, args = []) {
        try {
            // Prepare request data
            const requestData = {
                cmd: cmd,
                args: Array.isArray(args) ? args : [args]
            };

            // Encrypt request
            const encryptedRequest = crypt.encrypt(JSON.stringify(requestData), undefined, undefined, true).toString("base64");

            // Send HTTP request
            const response = await fetch(`${this.apiUrl}/execute`, {
                method: "POST",
                headers: {'content-type': 'application/json; charset=UTF-8'},
                body: JSON.stringify({data: encryptedRequest})
            });

            // Decrypt response
            const encryptedResponse = (await response.json()).data;
            const encryptedBytes = Buffer.from(encryptedResponse, 'base64');
            const decryptedResponse = crypt.decrypt(encryptedBytes);
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

    async healthCheck() {
        try {
            const response = await fetch(`${this.apiUrl}/health`);
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
    let configFile = 'config.json';
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
        } else if (args[i] === '--config' || args[i] === '-c') {
            if (i + 1 < args.length) {
                configFile = args[++i];
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
    return { apiUrl, configFile, commandArgs };
}

// CLI Interface
async function main() {
    try {
        // Parse command line arguments
        const { apiUrl, configFile, commandArgs } = parseCommandLineArgs();
        
        if (commandArgs.length === 0) {
            console.log('Usage:');
            console.log('  node client.js [options] <command> [args...]');
            console.log('  node client.js [options] --health');
            console.log('  node client.js [options] --interactive');
            console.log('\nOptions:');
            console.log('  --host, -h <host>     API server host (default: localhost)');
            console.log('  --port, -p <port>     API server port (default: 5000)');
            console.log('  --config, -c <file>   Config file path (default: config.json)');
            console.log('\nExamples:');
            console.log('  node client.js ls -la');
            console.log('  node client.js --host 192.168.1.100 --port 8080 ls -la');
            console.log('  node client.js -h api.example.com -p 443 echo "Hello World"');
            console.log('  node client.js --config /path/to/config.json pwd');
            console.log('  node client.js --interactive');
            process.exit(1);
        }

        // Initialize client with parsed parameters
        const client = new ShellCommandClient(apiUrl, configFile);
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
                const parts = trimmed.split(' ');
                const cmd = parts[0];
                const args = parts.slice(1);
                
                const result = await client.executeCommand(cmd, args);
                
                console.log(`\nExit Code: ${result.exit_code}`);
                if (result.stdout) console.log(`Stdout: ${result.stdout}`);
                if (result.stderr) console.log(`Stderr: ${result.stderr}`);
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
   
   const client = new ShellCommandClient('http://api.example.com:8080', 'config.json');
   const result = await client.executeCommand('ls', ['-la']);
   console.log(result);
*/
