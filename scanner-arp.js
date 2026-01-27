'use strict'

const Scanner = require('./scanner');
const Util = require('util');
const Exec = require('child_process').exec;
const ExecPromise = Util.promisify(Exec);
const Os = require('os');
const F = require('./functions');
const Path = require('path');

//CONSTANTS
const OS_WINDOWS = 'Windows_NT';
const OS_LINUX = 'Linux';
const OS_MAC = 'Darwin';

class ScannerARP extends Scanner {

    constructor() {
        super();
        this.osType = Os.type();
        this.arpScanAvailable = null;
        this.verbose = false;
    }

    /**
     * Check if arp-scan is available on the system
     * @returns {Promise<boolean>}
     */
    async checkArpScanAvailable() {
        if (this.arpScanAvailable !== null) {
            return this.arpScanAvailable;
        }

        try {
            if (this.osType === OS_WINDOWS) {
                // On Windows, check for arp-scan.exe in third_party directory
                const Fs = require('fs');
                const arpScanPath = Path.join(__dirname, 'third_party', 'arp-scan.exe');
                const exists = Fs.existsSync(arpScanPath);
                this.arpScanAvailable = exists;
                if (this.verbose && !exists) {
                    console.log('arp-scan.exe not found at:', arpScanPath);
                }
                return exists;
            } else {
                // Linux and macOS: check if arp-scan exists
                await ExecPromise('which arp-scan');
                this.arpScanAvailable = true;
                return true;
            }
        } catch (error) {
            this.arpScanAvailable = false;
            return false;
        }
    }


    /**
     * Scan ARP using arp-scan command (cross-platform)
     * @param {Object} params - { networkInterface, broadcastIP, timeout }
     * @returns {Promise<Array>} Array of {ip, mac} objects
     */
    async scanWithArpScan({ networkInterface, broadcastIP, timeout = 3000 }) {
        return new Promise(async (resolve, reject) => {
            const devices = [];
            const seenDevices = new Set();
            
            try {
                if (!networkInterface.cidr) {
                    throw new Error('networkInterface.cidr is required for arp-scan');
                }

                // Calculate network base address from CIDR (e.g., 10.10.1.242/24 -> 10.10.1.0/24)
                const Netmask = require('netmask').Netmask;
                let networkCIDR = networkInterface.cidr;
                
                try {
                    const block = new Netmask(networkInterface.cidr);
                    // Use network base address instead of interface IP
                    networkCIDR = `${block.base}/${block.bitmask}`;
                    if (this.verbose) {
                        console.log(`Using network base: ${networkCIDR} (from interface CIDR: ${networkInterface.cidr})`);
                    }
                } catch (e) {
                    // If parsing fails, use original CIDR
                    if (this.verbose) {
                        console.log(`Could not parse CIDR, using original: ${networkInterface.cidr}`);
                    }
                }

                let command;
                // ARP scan can take longer, especially for /24 networks (256 IPs)
                // Use a longer timeout: at least 30 seconds for /24, or timeout * 10 if larger
                const arpScanTimeout = Math.max(30000, timeout * 10);
                let execOptions = { timeout: arpScanTimeout };
                
                if (this.osType === OS_WINDOWS) {
                    // Windows: use arp-scan.exe from third_party directory
                    const arpScanPath = Path.join(__dirname, 'third_party', 'arp-scan.exe');
                    // Use absolute path and set working directory to avoid path issues
                    const arpScanDir = Path.join(__dirname, 'third_party');
                    execOptions.cwd = arpScanDir;
                    // Use relative path from the working directory
                    command = `arp-scan.exe -t ${networkCIDR}`;
                } else {
                    // Linux/macOS: use arp-scan command
                    command = `arp-scan --interface=${networkInterface.name} ${networkCIDR}`;
                }
                
                if (this.verbose) {
                    console.log(`ARP-scan timeout: ${arpScanTimeout}ms`);
                }

                if (this.verbose) {
                    console.log('ARP-scan command: ' + command);
                    if (execOptions.cwd) {
                        console.log('Working directory: ' + execOptions.cwd);
                    }
                }

                let result;
                try {
                    result = await ExecPromise(command, execOptions);
                } catch (execError) {
                    // exec throws an error even if the command produces output
                    // Check if we have stdout (command might have succeeded but returned non-zero exit code)
                    if (this.verbose) {
                        console.log('ExecPromise threw error, checking for output...');
                        console.log('  execError.stdout:', execError.stdout);
                        console.log('  execError.stderr:', execError.stderr);
                        console.log('  execError keys:', Object.keys(execError));
                    }
                    
                    if (execError.stdout || execError.stderr) {
                        // Use the error object as result - it contains stdout and stderr
                        result = {
                            stdout: execError.stdout || '',
                            stderr: execError.stderr || ''
                        };
                        if (this.verbose) {
                            console.log('Command returned error but has output, treating as success');
                            console.log('  Result stdout length:', result.stdout.length);
                            console.log('  Result stderr length:', result.stderr.length);
                        }
                    } else {
                        // No output, re-throw the error
                        if (this.verbose) {
                            console.log('No output found in error, re-throwing');
                        }
                        throw execError;
                    }
                }
                
                // Ensure result is defined before using it
                if (!result) {
                    throw new Error('No result from arp-scan command');
                }
                
                if (this.verbose) {
                    console.log('ARP-scan stdout length:', result.stdout ? result.stdout.length : 0);
                    console.log('ARP-scan stdout:', result.stdout);
                    if (result.stderr) {
                        console.log('ARP-scan stderr:', result.stderr);
                    }
                }
                
                // Parse output based on OS
                let parsedDevices = [];
                if (this.osType === OS_WINDOWS) {
                    parsedDevices = this._parseArpScanWindowsOutput(result.stdout || '', result.stderr || '');
                } else {
                    parsedDevices = this._parseArpScanLinuxOutput(result.stdout || '', result.stderr || '');
                }

                parsedDevices.forEach(device => {
                    // Ignore the broadcast address
                    if (device.ip === broadcastIP) {
                        if (this.verbose) {
                            console.log(`Ignoring broadcast address: ${device.ip} (${device.mac})`);
                        }
                        return;
                    }
                    
                    const deviceKey = `${device.ip}:${device.mac}`;
                    if (!seenDevices.has(deviceKey)) {
                        seenDevices.add(deviceKey);
                        devices.push(device);
                        this.ipArrayResults.push(device.ip);
                        this.emit(Scanner.EVENT_RESPONSE, device);
                        if (this.verbose) {
                            console.log(`ARP reply from: ${device.ip} (${device.mac})`);
                        }
                    } else {
                        if (this.verbose) {
                            console.log(`Skipped duplicate: ${device.ip} (${device.mac}) - key already seen: ${deviceKey}`);
                        }
                    }
                });
                
                if (this.verbose) {
                    console.log(`Total devices after deduplication: ${devices.length} (from ${parsedDevices.length} parsed)`);
                }

                resolve(devices);
            } catch (error) {
                // Improved error handling to show full error details
                const errorDetails = [];
                errorDetails.push(`Message: ${error.message}`);
                if (error.code !== undefined && error.code !== null) {
                    errorDetails.push(`Code: ${error.code}`);
                }
                
                // Log all error properties for debugging
                if (this.verbose) {
                    console.error('ARP-scan error - all properties:');
                    console.error('  error keys:', Object.keys(error));
                    for (const key of Object.keys(error)) {
                        if (key !== 'stack') {
                            console.error(`  ${key}:`, error[key]);
                        }
                    }
                }
                
                if (error.stdout) {
                    errorDetails.push(`Stdout: ${error.stdout.substring(0, 200)}${error.stdout.length > 200 ? '...' : ''}`);
                }
                if (error.stderr) {
                    errorDetails.push(`Stderr: ${error.stderr.substring(0, 200)}${error.stderr.length > 200 ? '...' : ''}`);
                }
                
                if (this.verbose) {
                    console.error('ARP-scan error details:');
                    errorDetails.forEach(detail => console.error('  ' + detail));
                }
                
                // Even if error, try to parse any output we got
                if (error.stdout || error.stderr) {
                    try {
                        let parsedDevices = [];
                        if (this.osType === OS_WINDOWS) {
                            parsedDevices = this._parseArpScanWindowsOutput(error.stdout || '', error.stderr || '');
                        } else {
                            parsedDevices = this._parseArpScanLinuxOutput(error.stdout || '', error.stderr || '');
                        }
                        
                        parsedDevices.forEach(device => {
                            // Ignore the broadcast address
                            if (device.ip === broadcastIP) {
                                if (this.verbose) {
                                    console.log(`Ignoring broadcast address: ${device.ip} (${device.mac})`);
                                }
                                return;
                            }
                            
                            const deviceKey = `${device.ip}:${device.mac}`;
                            if (!seenDevices.has(deviceKey)) {
                                seenDevices.add(deviceKey);
                                devices.push(device);
                                this.ipArrayResults.push(device.ip);
                                this.emit(Scanner.EVENT_RESPONSE, device);
                            }
                        });
                    } catch (parseError) {
                        // Ignore parse errors
                    }
                }
                
                // If we got some devices, resolve with them, otherwise throw the error
                if (devices.length > 0) {
                    resolve(devices);
                } else {
                    // Re-throw error with more details - always include stderr if available
                    const errorMsg = error.stderr || error.stdout || error.message || 'Unknown error';
                    const fullErrorMsg = errorDetails.join('; ');
                    throw new Error(`ARP-scan failed: ${fullErrorMsg}`);
                }
            }
        });
    }

    /**
     * Parse arp-scan Windows output
     * Format: "Reply that MAC is IP in TIME"
     * Example: "Reply that 5C:47:5E:8C:0A:C2 is 10.10.1.1 in 127.013700"
     * @param {string} stdout - Standard output from arp-scan.exe
     * @param {string} stderr - Standard error from arp-scan.exe
     * @returns {Array} Array of {ip, mac} objects
     */
    _parseArpScanWindowsOutput(stdout, stderr) {
        const devices = [];
        const content = (stdout + '\n' + stderr).trim();
        const lines = content.split('\n');

        // Pattern: "Reply that MAC is IP in TIME"
        const replyRegex = /Reply that\s+([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\s+is\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+in\s+/;

        if (this.verbose) {
            console.log(`Parsing ${lines.length} lines from arp-scan output`);
        }

        for (const line of lines) {
            const trimmedLine = line.trim();
            if (!trimmedLine) continue; // Skip empty lines
            
            const match = trimmedLine.match(replyRegex);
            if (match) {
                const mac = F.normalizeMAC(match[1]);
                const ip = match[2];
                
                if (F.isIP(ip) && F.isMAC(mac)) {
                    devices.push({ ip, mac });
                    if (this.verbose) {
                        console.log(`  Parsed: ${ip} -> ${mac}`);
                    }
                } else {
                    if (this.verbose) {
                        console.log(`  Skipped invalid: IP=${ip}, MAC=${mac}`);
                    }
                }
            } else if (this.verbose && trimmedLine.includes('Reply')) {
                console.log(`  No match for line: ${trimmedLine.substring(0, 80)}`);
            }
        }

        if (this.verbose) {
            console.log(`Total devices parsed: ${devices.length}`);
        }

        return devices;
    }

    /**
     * Parse arp-scan Linux/macOS output
     * Format: "IP\tMAC\t(Vendor)"
     * Example: "10.10.1.3\t98:17:3c:01:e8:f2\t(Unknown)"
     * @param {string} stdout - Standard output from arp-scan
     * @param {string} stderr - Standard error from arp-scan
     * @returns {Array} Array of {ip, mac} objects
     */
    _parseArpScanLinuxOutput(stdout, stderr) {
        const devices = [];
        const content = (stdout + '\n' + stderr).trim();
        const lines = content.split('\n');

        // Pattern: IP address, MAC address (tab or space separated)
        // Skip header lines and empty lines
        for (const line of lines) {
            // Skip header lines
            if (line.includes('Interface:') || 
                line.includes('Starting arp-scan') || 
                line.includes('WARNING:') ||
                line.trim() === '') {
                continue;
            }

            // Parse line: IP\tMAC\t(Vendor) or IP MAC (Vendor)
            const parts = line.trim().split(/\s+/);
            if (parts.length >= 2) {
                const ip = parts[0];
                const mac = parts[1];
                
                if (F.isIP(ip) && F.isMAC(mac)) {
                    devices.push({ 
                        ip, 
                        mac: F.normalizeMAC(mac) 
                    });
                }
            }
        }

        return devices;
    }


    /**
     * Start ARP broadcast scan
     * @param {Object} params - { networkInterface, broadcastIP, timeout, verbose }
     */
    async start({ networkInterface, broadcastIP, timeout = 3000, verbose = false }) {
        this.verbose = verbose;
        // Initialize scanner base class (required for buildScanResult())
        // ScannerARP doesn't use ipArrayToScan, but we need to initialize ipArrayResults
        super.start({ ipArrayToScan: [] });

        F.validateParamIp(broadcastIP);
        if (!networkInterface || !networkInterface.name) {
            throw new Error('networkInterface with name property is required');
        }

        if (!networkInterface.cidr) {
            throw new Error('networkInterface.cidr is required for ARP scan');
        }

        let devices = [];

        // Check if arp-scan is available
        const arpScanAvailable = await this.checkArpScanAvailable();
        
        if (!arpScanAvailable) {
            if (this.osType === OS_WINDOWS) {
                console.error('ERROR: ARP broadcast scan requires arp-scan.exe in third_party directory.');
                console.error('Please ensure arp-scan.exe is available in the third_party folder.');
                throw new Error('ARP broadcast scan requires arp-scan.exe on Windows');
            } else {
                console.error('ERROR: ARP broadcast scan requires arp-scan command.');
                console.error('Please install it with: sudo apt-get install arp-scan (Linux) or brew install arp-scan (macOS)');
                throw new Error('ARP broadcast scan requires arp-scan command');
            }
        }

        // Use arp-scan for all platforms
        try {
            devices = await this.scanWithArpScan({ networkInterface, broadcastIP, timeout });
            if (this.verbose) {
                console.log(`ARP-scan completed: found ${devices.length} devices`);
            }
        } catch (error) {
            if (this.verbose) {
                console.error(`ARP-scan error: ${error.message}`);
            }
            throw error;
        }

        // Emit complete event
        this.emit(Scanner.EVENT_COMPLETE, this.buildScanResult());

        return devices;
    }

}

module.exports = ScannerARP;
