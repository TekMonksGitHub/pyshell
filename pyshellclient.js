#!/usr/bin/env node

/**
 * Node.js Client for AES256-CTR Encrypted Shell Command API
 * Communicates with the Python Flask Shell API using encrypted JSON
 * 
 * AI Generated - Claude then manually modified.
 * 
 * Needs Monkshu libraries - crypt and httpClient
 * (C) Tekmonks. All rights reserved.
 */

if ((!global.CONSTANTS) && (!process.env.MONKSHU_HOME)) {console.error("\nError: MONKSHU_HOME not set.\n"); process.exit(1);}
const MONKSHULIBDIR = global.CONSTANTS ? CONSTANTS.LIBDIR : process.env.MONKSHU_HOME+"/backend/server/lib";

const fs = require("fs");
const path = require("path");
const util = require("util");
const crypt = require(`${MONKSHULIBDIR}/crypt.js`);
const processargs = require(`${MONKSHULIBDIR}/processargs.js`);
const execasync = util.promisify(require("child_process").exec);
global.LOG = console; global.LOG.info = _=>{};  // this quitens the HTTP client info messages
const {fetch} = require(`${MONKSHULIBDIR}/httpClient.js`);

class ShellCommandClient {
    constructor(apiUrl = 'http://localhost:5000', aesKey) {this.apiUrl = apiUrl; this.aesKey = aesKey;}

    async fetchRequest(requestData, endpoint, timeout) {
        try {
            const encryptedRequest = crypt.encrypt(JSON.stringify(requestData), this.aesKey,
                undefined, true).toString("base64");

            // Send HTTP request
            const response = await fetch(`${this.apiUrl}/${endpoint}`, {
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

    async executeCommand(cmd, args = [], timeout) {
        // Prepare request data
        const requestData = {cmd: cmd, args: Array.isArray(args) ? args : [args]};
        return await this.fetchRequest(requestData, "execute", timeout);
    }

    async executeScript(script, scriptfile_path, args = [], shell="/bin/bash", timeout) {
        // Prepare request data
        const requestData = {script, scriptfile_path, args: Array.isArray(args) ? args : [args], shell};
        return await this.fetchRequest(requestData, "shellscript", timeout);
    }

    async healthCheck(timeout) {
        const requestData = {health: true};
        return await this.fetchRequest(requestData, "health", timeout);
    }

    async deploy(host, port, id, password, pyshell_path, pyshell_user, pyshell_aeskey, 
            pyshell_listening_host, pyshell_listening_port, pyshell_process_default_timeout) {
        const args = [`'${__dirname}/deploy/deploy.sh'`, host, port, id, `'${password}'`, `'${pyshell_path}'`,
            pyshell_aeskey, pyshell_listening_host, pyshell_listening_port, pyshell_user, pyshell_process_default_timeout];
        const cmd = args.join(' ');
        try {const {stdout, stderr} = await execasync(cmd); return {stdout, stderr, exit_code: 0};} 
        catch (error) {return {stdout: undefined, stderr: error.message, exit_code: error.status};}
    }
}

// Parse command line arguments for host and port
function parseCommandLineArgs() {
    argMap = { 
        "__description": "\nPyShellClient. (C) 2024 Tekmonks.",
        "h": {long: "host", required: true, minlength: 1, help: "Host to connect to."},
        "p": {long: "port", required: true, minlength: 1, help: "Port to connect to."},
        "k": {long: "key", required: false, minlength: 1, help: "AES key for the connection. Default: Monkshu key."},
        "m": {long: "command", required: false, minlength: 1, help: "Command and [args...] if specified"}, 
        "s": {long: "shellscript", required: false, minlength: 1, help: "Shell script and [args...] if specified"},
        "d": {long: "deploy", required: false, minlength: 9, help: "Deployment arguments ssh_host ssh_port ssh_id ssh_password pyshell_path pyshell_user pyshell_aeskey pyshell_host pyshell_port pyshell_timeout"},
        "t": {long: "health", required: false, help: "Remote server's health"},
        "i": {long: "interactive", required: false, help: "Run an interactive session"},
        "__extra_help": "\nExamples\n"+
            `\tnode ${process.argv[1]} --command ls -la\n`+
            `\tnode ${process.argv[1]} -h api.example.com -p 443 --shellscript ./test.sh arg1 arg2\n`+
            `\tnode ${process.argv[1]} --host 192.168.1.100 --port 8080 --command ls -la\n`+
            `\tnode ${process.argv[1]} -h api.example.com -p 443 echo "Hello World"\n`+
            `\tnode ${process.argv[1]} --key "MySecret30CharacterMinimumKey" --host 192.168.1.100 --port 8080 --command ls -la\n`+
            `\tnode ${process.argv[1]} -h api.example.com -p 443 --interactive\n`
    }
    const args = processargs.getArgs(argMap, undefined, undefined, true);
    if (!args) return;
    else return { apiUrl: `http://${args.host[0]}:${args.port[0]}`, aesKey: args.key?.[0], commandArgs: args };
}

// Display results to the console
function displayResult(result, interactive) {
    // Display results
    if (!interactive) console.log('\n--- Execution Result ---');

    if (result.stdout) console.log(`${!interactive?'\n':''}Stdout: \n${result.stdout}`);
    if (result.stderr) console.log(`${!interactive?'\n':''}Stderr: \n${result.stderr}`);
    console.log(`${!interactive?'':'\n'}Exit Code: ${result.exit_code}${!interactive?'':'\n'}`);
}

// CLI Interface
async function main() {
    try {
        // Parse command line arguments
        const parseResult = parseCommandLineArgs(); if (!parseResult) throw new Error(`Command line error.`);
        const { apiUrl, aesKey, commandArgs } = parseResult;

        // Initialize client with parsed parameters
        let client = new ShellCommandClient(apiUrl, aesKey);
        console.log(`Connecting to API at: ${apiUrl}`);

        // Handle special commands
        if (commandArgs.health) {
            const health = await client.healthCheck();
            console.log('Health Check Result:', JSON.stringify(health, null, 2));
            return;
        }

        if (commandArgs.interactive) {
            await interactiveMode(client);
            return;
        }

        if (commandArgs.shellscript) {
            const script = await fs.promises.readFile(commandArgs.shellscript[0], "utf8");
            const scriptfile_path = `/tmp/${path.basename(commandArgs.shellscript[0])}`;
            const scriptargs = commandArgs.shellscript[1];
            const result = await client.executeScript(script, scriptfile_path, scriptargs);
            displayResult(result);
            return;
        }

        if (commandArgs.deploy) {
            const dpArgs = commandArgs.deploy, host = dpArgs[0], port = dpArgs[1], id = dpArgs[2];
            const password = dpArgs[3], pyshell_path = dpArgs[4];
            const pyshell_user = dpArgs[5], pyshell_aeskey = dpArgs[6];
            const pyshell_listening_host = dpArgs[7], pyshell_listening_port = dpArgs[8];
            const pyshell_process_default_timeout = dpArgs[9] || 1800;
            const result = await client.deploy(host, port, id, password, pyshell_path, pyshell_user,
                pyshell_aeskey, pyshell_listening_host, pyshell_listening_port, pyshell_process_default_timeout);
            displayResult(result);
            return;
        }

        // Execute command
        if (commandArgs.command) {
            const cmd = commandArgs.command[0];
            const cmdArgs = commandArgs.command.slice(1);

            console.log(`Executing: ${cmd} ${cmdArgs.join(' ')}`);
            const result = await client.executeCommand(cmd, cmdArgs);
            displayResult(result); 
            return;
        }

        console.error("Error: Unknown command");
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

    const askCommand = async () => {
        const health = await client.healthCheck()
        rl.question(`${health.user+'@'+health.hostname} # `, async (input) => {
            const trimmed = input.trim();
            if (trimmed === 'exit' || trimmed === 'quit') {rl.close(); return;}
            if (trimmed === '') {askCommand(); return;}

            try {
                if (trimmed.startsWith('shellscript ')) {
                    const parts = trimmed.split(' ');
                    const scriptPath = parts[1];
                    const script = await fs.promises.readFile(scriptPath, "utf8");
                    const remoteScriptPath = "/tmp/"+path.basename(scriptPath);
                    const result = await client.executeScript(script, remoteScriptPath, parts.slice(2));
                    displayResult(result, true);
                    setImmediate(_=>askCommand());
                    return;
                }

                if (trimmed === 'pyshellhealth') {
                    const health = await client.healthCheck();
                    console.log('Health Check Result:', JSON.stringify(health, null, 2));
                    setImmediate(_=>askCommand());
                    return;
                }

                if (trimmed.startsWith('deploy ')) {
                    const parts = trimmed.split(' ');
                    const host = parts[1], port = parts[2], id = parts[3];
                    const password = parts[4], pyshell_path = parts[5];
                    const pyshell_user = parts[6], pyshell_aeskey = parts[7];
                    const pyshell_listening_host = parts[8], pyshell_listening_port = parts[9];
                    const pyshell_process_default_timeout = parts[10] || 1800;
                    const result = await client.deploy(host, port, id, password, pyshell_path, pyshell_user,
                        pyshell_aeskey, pyshell_listening_host, pyshell_listening_port, pyshell_process_default_timeout);
                    // Display results
                    displayResult(result, true);
                    setImmediate(_=>askCommand());
                    return;
                }

                if (trimmed.startsWith('reconnect ')) {
                    const parts = trimmed.split(' ');
                    const aeskey = parts[1], host = parts[2], port = parts[3];
                    const apiUrl = `http://${host}:${port}`;
                    client = new ShellCommandClient(apiUrl, aeskey);
                    console.log(`Connecting to API at: ${apiUrl}`);
                    setImmediate(_=>askCommand());
                    return;
                }

                // now it is executed as a command line command
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
                displayResult(result, true);
                setImmediate(_=>askCommand());
            } catch (error) {
                console.error('Error:', error.message+"\n"+error.stack);
                setImmediate(_=>askCommand());
                return;
            }
        });
    };

    askCommand();
}

// Export for use as module
module.exports = { ShellCommandClient };

// Run CLI if called directly
if (require.main === module) {main();}