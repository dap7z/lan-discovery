'use strict';

//LIBRARIES
const Os = require('os');
const Util = require('util');
const Exec = require('child_process').exec;
const ExecPromise = Util.promisify(Exec);
const Netmask = require('netmask').Netmask;

const Scanner = require('./scanner');
const ScannerICMP = require('./scanner-icmp');
const ScannerTCP = require('./scanner-tcp');
const ScannerARP = require('./scanner-arp');
const EventEmitter = require('events');
const F = require('./functions');


//CONSTANTS
const OS_WINDOWS = 'Windows_NT';
const OS_LINUX = 'Linux';
const OS_MAC = 'Darwin';

const EVENT_SCAN_RESPONSE = 'scanResponse';
const EVENT_SCAN_COMPLETE = 'scanComplete';
const EVENT_DEVICE_INFOS = 'deviceInfos';
const EVENT_DEVICES_INFOS = 'devicesInfos';
const EVENT_ARP_RESPONSE = 'arpResponse';
const EVENT_ARP_COMPLETE = 'arpComplete';

class LanDiscovery extends EventEmitter
{
    //define events emitted :
    static get EVENT_SCAN_RESPONSE(){ return EVENT_SCAN_RESPONSE }
    static get EVENT_SCAN_COMPLETE(){ return EVENT_SCAN_COMPLETE }
    static get EVENT_DEVICE_INFOS(){ return EVENT_DEVICE_INFOS }
    static get EVENT_DEVICES_INFOS(){ return EVENT_DEVICES_INFOS }
    static get EVENT_ARP_RESPONSE(){ return EVENT_ARP_RESPONSE }
    static get EVENT_ARP_COMPLETE(){ return EVENT_ARP_COMPLETE }

    /**
     * Constructor
     * (you can pass options)
     *
     * Example: new LanDiscovery({ verbose:true, timeout:60 })
     * @param {Object} options The options to apply
     */
    constructor(options) {
        super();
        //initialization of class attributes
        this.verbose = false;
        this.timeout = 10;
        if (options){
            if(options.verbose) {
                this.verbose = options.verbose;
            }
            if(options.timeout) {
                if (options.timeout < 1 || options.timeout > 60) throw new Error(`Invalid timeout: ${options.timeout}. Please choose a timeout between 1 and 60s`);
                else this.timeout = parseInt(options.timeout) || options.timeout.toFixed(0);
            }
        }
        this.osType = Os.type();
        switch(this.osType){
            case OS_WINDOWS : break;
            case OS_LINUX : break;
            case OS_MAC : break;
            default : throw new Error('Unsupported OS: ' + this.osType);
        }
        this.scannerICMP = new ScannerICMP();
        this.scannerTCP = new ScannerTCP();
        this.scannerARP = new ScannerARP();

        // EVENT MANAGEMENT
        // - one device responds to ping :
        this.scannerICMP.on(Scanner.EVENT_RESPONSE, (ip) => {
            this.emit(EVENT_SCAN_RESPONSE, ip);
            let myPromise = this.deviceInfos(ip);
            myPromise.then((device) => {
                this.emit(EVENT_DEVICE_INFOS, device)
            })
            this.devicesInfosPromises.push(myPromise);
        });
        // - the ping scan is complete :
        this.scannerICMP.on(Scanner.EVENT_COMPLETE, (data) => {
            this.emit(EVENT_SCAN_COMPLETE, data);
            // we retrieved information from all devices that responded to the ping.
            Promise.all(this.devicesInfosPromises).then( (devicesArray) => {
                this.emit(EVENT_DEVICES_INFOS, devicesArray);
            });
        });

        // ARP EVENT MANAGEMENT
        // - one device responds to ARP broadcast :
        this.scannerARP.on(Scanner.EVENT_RESPONSE, (device) => {
            this.emit(EVENT_ARP_RESPONSE, device);
        });
        // - the ARP scan is complete :
        this.scannerARP.on(Scanner.EVENT_COMPLETE, (data) => {
            this.emit(EVENT_ARP_COMPLETE, data);
        });

        // Checking the availability of the 'host' command on Linux
        if(this.osType === OS_LINUX){
            this._checkHostCommand();
        }
    }

    /**
     * Verify if the command 'host' is available on a linux computer
     * Show warning if not installed
     * @private
     */
    _checkHostCommand() {
        // Asynchronous verification without blocking initialization
        ExecPromise('which host').then(() => {
            // The command exists, everything is fine.
        }).catch(() => {
            // The command is not available, show warning.
            console.warn('WARNING: Command "host" is not available on this computer. This command is necessary to determine others PCs hostnames');
            console.warn('   For installing "host" on Raspberry Pi / Debian / Ubuntu, execute :');
            console.warn('   sudo apt-get update && sudo apt-get install dnsutils');
        });
    }

    /**
     * Check if the current process has administrator/root privileges
     * @returns {Promise<boolean>} True if admin/root, false otherwise
     * @private
     */
    async _checkAdminPrivileges() {
        try {
            if (this.osType === OS_WINDOWS) {
                // Windows: use 'net session' which requires admin privileges
                // If it succeeds, we have admin rights
                await ExecPromise('net session', { timeout: 2000 });
                return true;
            } else {
                // Linux/macOS: check if user ID is 0 (root)
                const result = await ExecPromise('id -u', { timeout: 2000 });
                const uid = parseInt(result.stdout.trim(), 10);
                return uid === 0;
            }
        } catch (error) {
            // Command failed, no admin/root privileges
            return false;
        }
    }
	
	/**
     * Retrieves the network's arp table (require previously executed os ping scan)
     * (warning arp table does not works well on virtualbox debian 9 : show only one entry ...)
     * same problem with vmware esxi or not ?  //TODO: test on ubuntu web server
     */
    //TESTED ON : WINDOWS 7, DEBIAN 9
    async arpTable() {
        return new Promise((resolve, reject) => {
            let flag = '';
            if(this.osType === OS_WINDOWS){
                flag = '-a';  //on windows : -a is required even for single IP translation
            }else{
                flag = '-n';  //on debian : show ip in column Address
            }
            let args = ['arp', flag];

            let command = args.join(' ');
            // Get the Address Resolution Protocol cache
            ExecPromise(command).then( (commandResult) => {
                if(commandResult.stderr){
                    throw new Error(commandResult.stderr);
                }
                /*
                  Split the table into rows

                  #Expected output (windows):
                  Interface: 192.168.137.1 --- 0x2
                      Internet Address      Physical Address      Type
                      192.168.1.255         ff-ff-ff-ff-ff-ff     static
                      192.168.2.1           04-a1-51-1b-12-92     dynamic
                      224.0.0.22            01-00-5e-00-00-16     static

                  #Expected output (linux):
                  Adresse                  TypeMap AdresseMat          Indicateurs           Iface
                  10.0.2.2                 ether   52:54:00:12:35:02   C                     enp0s3

                */
                const rows = commandResult.stdout.split('\n');
                /**
                 * The arp table
                 */
                const table = [];
                // Loop over each row
                for (const row of rows) {
                    // Trim the white space from the row and collapse double spaces
                    let words = row.trim()
                        .replace(/\s+/g, ' ')
                        .split(' ');
                    // then split the row into columns of ip, mac, type
                    let rIp = null;
                    let rMac = null;
                    if(this.osType === OS_WINDOWS){
                        rIp = words[0];
                        rMac = words[1];
                    }else{
                        rIp = words[0];
                        rMac = words[2];
                    }

                    if (!F.isMAC(rMac)){
                        //mac isn't a valid MAC address, this is a header row so we can just ignore it.
                        continue;
                    }
                    // Add this row to the table
                    table.push({
                        ip: rIp,
                        mac: F.normalizeMAC(rMac),
                    });
                }
                // Resolve with the populated arp table
                resolve(table);
            })
            .catch( (error) => {
                reject(error);
            });
        });
    }


    /**
     * Get all informations about a device identified by his IP address
     * @param ip
     * @param mac Optional MAC address if already known (from ARP scan)
     * @returns {Promise<{ip: *, name: *, mac: null}>}
     */
    async deviceInfos(ip, mac = null){
        F.validateParamIp(ip);
        // We already know the IP responds to ping (from the ping scan with net-ping)
        // The OS ARP table should already be updated by the ping scan, so we can read it directly
        // No need for osPingCommand which is redundant and causes delays
        if(mac===null){
            let r1 = await this.deviceMAC(ip);
            mac = (r1 ? r1.mac : null); //mac is null for self scan (not in arp table)
        }
        let r2 = await this.deviceName(ip);
        return {
            'name' : r2,
            'ip' : ip,
            'mac' : mac,
            'respondsToPing' : true
        };
    }
	
	
	/**
     * Get the IP address for given MAC address
     * Warning : can return null if the lan has not been scanned recently
     * @param mac The MAC address
     */
    //TESTED ON : WINDOWS 7,
    async deviceIP(mac) {
        if (!F.isMAC(mac)){
            throw Error('Invalid MAC');
        }
        mac = F.normalizeMAC(mac);
        // Get the arp table
        const arpTable = await this.arpTable();
        // Try to find a match in the table
        const match = arpTable.reduce((prev, curr) => (curr.mac === mac ? curr.ip : prev), '');
        // If match was found then return the ip, otherwise return null
        return (match? match : null);
    }
	
	
	/**
     * Get the MAC address for given IP address : look in os arp table for a specific ip addresses
     * Warning : can return null if you haven't previously send a ping request
     * @param {String} ip
     */
    //TESTED ON : WINDOWS 7, DEBIAN 9
    async deviceMAC(ip) {
        return new Promise((resolve) => {
            F.validateParamIp(ip);

            let flag = '';
            if(this.osType === OS_WINDOWS){
                flag = '-a'; //on windows : -a is required even for single IP translation
            }else{
                flag = '-n';  //on debian : show ip in column Address
            }
            let args = ['arp', flag];

            args.push(ip);
            let command = args.join(' ');
            if(this.verbose) console.log('command: ' + command);

            ExecPromise(command).then( (commandResult) => {
                if(commandResult.stderr){
                    throw new Error(commandResult.stderr);
                }
                const rows = commandResult.stdout.split('\n');
                // Loop over each row
                for (const row of rows) {
                    if(this.verbose) console.log('command result row: ' + row);

                    // Trim the white space from the row and collapse double spaces
                    let words = row.trim()
                        .replace(/\s+/g, ' ')
                        .split(' ');
                    // then split the row into columns of ip, mac, type
                    let rIp = null;
                    let rMac = null;
                    if(this.osType === OS_WINDOWS){
                        rIp = words[0];
                        rMac = words[1];
                    }else{
                        rIp = words[0];
                        rMac = words[2];
                    }

                    if (F.isMAC(rMac)){
                        resolve({
                            ip : rIp,
                            mac : F.normalizeMAC(rMac),
                        });
                    }
                    //else : mac isn't a valid MAC address, this is a header row so we can just ignore it.
                }
                resolve(null);
            })
            .catch( (error) => {
                if(this.verbose) console.error('ERROR: ', error);
                resolve(null);
            });
        });
    }
	
	
	/**
     * Get hostname from ip address
     * https://www.plesk.com/blog/various/reverse-dns-lookup/
     * @param {String} ip
     */
    //TESTED ON : WINDOWS 7, DEBIAN 9
    async deviceName(ip) {
        return new Promise((resolve) => {
            F.validateParamIp(ip);
            // Ensure timeout has a default value to avoid "undefined" in command
            const timeout = this.timeout || 4;
            let exe = 'host';
            let flag = '-W='+timeout;
            if(this.osType === OS_WINDOWS){
                exe = 'nslookup';
                flag = '-timeout='+timeout;
            }
            let args = [exe, flag];
            args.push(ip);
            let command = args.join(' ');
            if(this.verbose) console.log('command: ' + command);

            ExecPromise(command).then( (commandResult) => {
                if(commandResult.stderr){
                    throw new Error(commandResult.stderr);
                }
                let hostname = null;
                let rows = commandResult.stdout.split('\n');

                switch(this.osType){
                    case OS_WINDOWS :
                        if(rows.length>3){
                            //On windows, we can only rely on line number to parse hostname
                            //nslookup -timeout=60 192.168.1.66
                            //Name :    redminote2-redmi-13.home
                            //Nom :    redminote2-redmi-13.home
                            //... depending on windows language
                            hostname = rows[3].trim()
                                .replace(/\s+/g, ' ')
                                .split(' ')
                                .pop();
                        }
                        break;
                    case OS_LINUX :
                    case OS_MAC :
                        //On debian command "host 192.168.1.10" output :
                        //10.1.168.192.in-addr.arpa domain name pointer pc-damien.home.
                        //(host command is also available on Mac OS)
                        hostname = rows[0].trim() //first row
                            .replace(/\s+/g, ' ')
                            .split(' ')
                            .pop()
                            .slice(0,-1); // remove final point
                        break;
                }

                resolve(hostname);
            }).catch( (error) => {
                if(this.verbose) console.error('ERROR: ', error);
                //WINDOWS 7 : ERROR:  Error: *** UnKnown ne parvient pas à trouver 192.168.1.22 : Non-existent domain
                resolve(null);
            });

        });
    }
	

    /**
     * Return active network informations
     */
    async getDefaultInterface() {
        const DefaultInterface = require('./utils/default-interface-util.js');
        let data = await DefaultInterface.v4();
        if(data === null){
            throw new Error("default gateway cannot be determined");
        }

        //we need cdir notation of the lan, so we translate 192.168.1.1/255.255.255.0 to 192.168.1.1/24
        //(to remove Netmask dependencie, we might use ipaddr.js plugin function : prefixLengthFromSubnetMask(), but still need a way to determine network address...)
        // Use address instead of gateway if gateway is null (fallback case)
        const networkBase = data.gateway || data.address;
        let block = new Netmask(networkBase + '/' + data.netmask);

        return {
            name: data.name,
            cidr: data.cidr,
            ip_address: data.address,
            mac_address: F.normalizeMAC(data.mac),
            fullmask: data.netmask,
            bitmask: block.bitmask,
            network: block.base,
            family: data.family,
            gateway_ip: data.gateway,
        };
    }


    /**
     * isMAC (internal function exposed)
     */
    static isMAC(mac){ return  F.isMAC(mac) };


    /**
     * isIP (internal function exposed)
     */
    static isIP(ip){ return  F.isIP(ip) };


    /**
     * Start the lan scan (Node ICMP Requests) and return the class object
     */
    startScan(objParam){
        F.validateParamIpArray(objParam.ipArrayToScan);
        this.devicesInfosPromises = [];
        this.scannerICMP.start(objParam);
        return this;
    }

    /**
     * Start hybrid scan: ARP broadcast first, then ping only on discovered IPs
     * This method combines ARP broadcast (low impact) + ping (L3 liveliness check)
     * @param {Object} objParam - { networkInterface, timeout, verbose, interval }
     * @param {Object} objParam.networkInterface - Network interface object (required)
     * @param {number} objParam.timeout - Timeout in milliseconds (default: 3000)
     * @param {boolean} objParam.verbose - Enable verbose logging (default: false)
     * @param {number} objParam.interval - Delay between ICMP pings in milliseconds (default: 0)
     *   - 0ms: No delay (all pings sent simultaneously)
     *   - 100ms: Occasional use, home LAN (5min for /24)
     *   - 200ms: Production/sensitive (10min) - recommended, zero perceptible impact
     *   - 500ms: Paranoid/critical network
     * @returns {Promise<This>}
     */
    async startHybridScan(objParam = {}){
        if (!objParam.networkInterface) {
            throw new Error('networkInterface is required for hybrid scan');
        }

        // Check admin/root privileges (required for ARP scan)
        const hasAdminRights = await this._checkAdminPrivileges();
        if (!hasAdminRights) {
            throw new Error('root/administrator rights are required for hybrid scan');
        }

        const networkInterface = objParam.networkInterface;
        const timeout = objParam.timeout || 3000;
        const verbose = objParam.verbose !== undefined ? objParam.verbose : this.verbose;
        const interval = objParam.interval !== undefined ? objParam.interval : 0;

        // Calculate broadcast IP from network interface
        const Netmask = require('netmask').Netmask;
        const block = new Netmask(networkInterface.cidr);
        const broadcastIP = block.broadcast;

        if (this.verbose || verbose) {
            console.log('Starting hybrid scan: ARP "broadcast" + reactive ping on discovered IPs');
            console.log(`Network: ${networkInterface.cidr}, Broadcast: ${broadcastIP}`);
            console.log(`Ping interval: ${interval}ms`);
        }

        // Variables for ping queue management
        const pingQueue = [];
        const pingInProgress = new Set();
        const pingCompleted = new Map();
        const arpDeviceMap = new Map();
        let lastPingTime = 0;
        let arpScanComplete = false;
        const NetPing = require('net-ping');
        
        // Create a shared net-ping session for all pings
        const sharedPingSession = NetPing.createSession({ timeout, retries: 0 });

        // Function to check ping and emit EVENT_DEVICES_INFOS
        const checkAndEmitDevicesInfos = () => {
            if (!arpScanComplete) {
                if (this.verbose || verbose) {
                    console.log('checkAndEmitDevicesInfos: ARP scan not complete yet');
                }
                return; // The ARP scan is not yet complete
            }
            
            if (pingInProgress.size > 0 || pingQueue.length > 0) {
                if (this.verbose || verbose) {
                    console.log(`checkAndEmitDevicesInfos: Still ${pingInProgress.size} pings in progress, ${pingQueue.length} in queue`);
                }
                return; // There are still pings in progress or pending
            }
            
            // All pings are finished, build the final results table
            const allDevices = Array.from(pingCompleted.values());
            
            if (this.verbose || verbose) {
                console.log(`checkAndEmitDevicesInfos: All pings complete. Found ${allDevices.length} devices in pingCompleted`);
            }
            
            // Sort results table by IP address
            allDevices.sort((a, b) => {
                const ipA = a.ip.split('.').map(Number);
                const ipB = b.ip.split('.').map(Number);
                for (let i = 0; i < 4; i++) {
                    if (ipA[i] !== ipB[i]) {
                        return ipA[i] - ipB[i];
                    }
                }
                return 0;
            });
            
            // Free resources
            sharedPingSession.close();
            
            // Restore default ARP handlers
            this.scannerARP.removeAllListeners(Scanner.EVENT_RESPONSE);
            this.scannerARP.removeAllListeners(Scanner.EVENT_COMPLETE);
            this.scannerARP.on(Scanner.EVENT_RESPONSE, (device) => {
                this.emit(EVENT_ARP_RESPONSE, device);
            });
            this.scannerARP.on(Scanner.EVENT_COMPLETE, (data) => {
                this.emit(EVENT_ARP_COMPLETE, data);
            });
            
            if (this.verbose || verbose) {
                console.log(`All pings complete: emitting devicesInfos for ${allDevices.length} devices`);
            }
            
            // Send completion events EVENT_SCAN_COMPLETE and EVENT_DEVICES_INFOS
            this.emit(EVENT_SCAN_COMPLETE, {
                ipArray: allDevices.map(d => d.ip),
                scanCount: allDevices.length,
                scanTimeMS: 0,
                scanAverageMS: 0
            });
            this.emit(EVENT_DEVICES_INFOS, allDevices);
        };

        // Function to perform a ICMP request
        const executePing = () => {
            if (pingQueue.length === 0) {
                return;
            }
            
            const { ip, mac } = pingQueue.shift();
            pingInProgress.add(ip);
            lastPingTime = Date.now();
            
            if (this.verbose || verbose) {
                console.log(`Pinging ${ip} (${mac})`);
            }
            
            sharedPingSession.pingHost(ip, async (error) => {
                pingInProgress.delete(ip);
                
                const knownMAC = arpDeviceMap.get(ip) || mac;
                
                try {
                    const deviceInfo = await this.deviceInfos(ip, knownMAC);
                    deviceInfo.respondsToPing = !error;
                    pingCompleted.set(ip, deviceInfo);
                    
                    this.emit(EVENT_DEVICE_INFOS, deviceInfo);
                    
                    if (!error) {
                        this.emit(EVENT_SCAN_RESPONSE, ip);
                    }
                } catch (e) {
                    // In case of error, create a minimal deviceInfo for the device
                    const deviceInfo = {
                        ip: ip,
                        mac: knownMAC,
                        name: null,
                        respondsToPing: !error
                    };
                    pingCompleted.set(ip, deviceInfo);
                    this.emit(EVENT_DEVICE_INFOS, deviceInfo);
                    
                    if (!error) {
                        this.emit(EVENT_SCAN_RESPONSE, ip);
                    }
                }
                launchNextPing();
                // Check if we can emit the final results
                checkAndEmitDevicesInfos();
            });
        };

        // Function to launch the next ping while respecting the interval
        const launchNextPing = () => {
            if (pingQueue.length === 0) {
                return; // Queue vide
            }
            
            // If interval = 0, multiple pings can be launched in parallel.
            // Otherwise, we limit it to one ping at a time to respect the interval
            if (interval > 0 && pingInProgress.size > 0) {
                return; // A ping is already in progress and we must respect the interval
            }
            
            const now = Date.now();
            const timeSinceLastPing = now - lastPingTime;
            
            if (interval === 0 || timeSinceLastPing >= interval) {
                // Delay respected, launch immediately
                executePing();
            } else {
                // Schedule the ping after the remaining timeout
                const delay = interval - timeSinceLastPing;
                setTimeout(() => {
                    executePing();
                }, delay);
            }
        };

        // Function to add a ping to the queue
        const schedulePing = (ip, mac) => {
            if (pingInProgress.has(ip) || pingCompleted.has(ip)) {
                if (this.verbose || verbose) {
                    console.log(`schedulePing: Skipping ${ip} (already in progress or completed)`);
                }
                return; // Ping already in progress or completed
            }
            
            pingQueue.push({ ip, mac });
            arpDeviceMap.set(ip, mac);
            
            if (this.verbose || verbose) {
                console.log(`schedulePing: Added ${ip} to queue (queue size: ${pingQueue.length})`);
            }
            
            launchNextPing();
        };

        // Listen for ARP events (temporarily replace the default handlers)
        const arpResponseHandler = (device) => {
            this.emit(EVENT_ARP_RESPONSE, device);
            if (this.verbose || verbose) {
                console.log(`arpResponseHandler: Received ARP response for ${device.ip} (${device.mac})`);
            }
            schedulePing(device.ip, device.mac);
        };
        
        const arpCompleteHandler = (data) => {
            this.emit(EVENT_ARP_COMPLETE, data);
            arpScanComplete = true;
            
            if (this.verbose || verbose) {
                console.log(`ARP scan complete. Waiting for ${pingInProgress.size + pingQueue.length} pending pings to finish...`);
            }
            
            // checkAndEmitDevicesInfos() will be automatically called in executePing() after each ping is completed.
            // No need to call it here unless no ping has been initiated (empty queue and none in progress).
            if (pingInProgress.size === 0 && pingQueue.length === 0) {
                checkAndEmitDevicesInfos();
            }
        };

        // Remove the default handlers and add our own
        this.scannerARP.removeAllListeners(Scanner.EVENT_RESPONSE);
        this.scannerARP.removeAllListeners(Scanner.EVENT_COMPLETE);
        this.scannerARP.on(Scanner.EVENT_RESPONSE, arpResponseHandler);
        this.scannerARP.on(Scanner.EVENT_COMPLETE, arpCompleteHandler);

        // Start the ARP scan (pings will be sent sequentially via events)
        try {
            await this.scannerARP.start({
                networkInterface: networkInterface,
                broadcastIP: broadcastIP,
                timeout: timeout,
                verbose: verbose
            });
        } catch (error) {
            // Close the session if an error occurs.
            sharedPingSession.close();
            
            // Restore default handlers
            this.scannerARP.removeAllListeners(Scanner.EVENT_RESPONSE);
            this.scannerARP.removeAllListeners(Scanner.EVENT_COMPLETE);
            this.scannerARP.on(Scanner.EVENT_RESPONSE, (device) => {
                this.emit(EVENT_ARP_RESPONSE, device);
            });
            this.scannerARP.on(Scanner.EVENT_COMPLETE, (data) => {
                this.emit(EVENT_ARP_COMPLETE, data);
            });
            
            throw new Error('ARP scan failed, error: ' + (error.message || error.toString() || 'Unknown error'));
        }
        
        // If (no device has been discovered) AND (all pings have completed) => Then emit completion events
        // Note: This check is performed after the ARP scan, but we wait until all pings are complete.
        // via checkAndEmitDevicesInfos() which will be called in executePing() after each ping is completed
        
        return this;
    }


}

/**
 * Export class LanDiscovery
 */
module.exports = LanDiscovery;

/**
 * Export CIDR range utility function (replacement for cidr-range package)
 */
module.exports.cidrRange = require('./utils/cidr-range-util');