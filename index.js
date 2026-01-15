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
const EventEmitter = require('events');
const F = require('./functions');

const Ping = require('ping');


//CONSTANTS
const OS_WINDOWS = 'Windows_NT';
const OS_LINUX = 'Linux';
const OS_MAC = 'Darwin';

const EVENT_SCAN_RESPONSE = 'scanResponse';
const EVENT_SCAN_COMPLETE = 'scanComplete';
const EVENT_DEVICE_INFOS = 'deviceInfos';
const EVENT_DEVICES_INFOS = 'devicesInfos';

class LanDiscovery extends EventEmitter
{
    //define events emitted :
    static get EVENT_SCAN_RESPONSE(){ return EVENT_SCAN_RESPONSE }
    static get EVENT_SCAN_COMPLETE(){ return EVENT_SCAN_COMPLETE }
    static get EVENT_DEVICE_INFOS(){ return EVENT_DEVICE_INFOS }
    static get EVENT_DEVICES_INFOS(){ return EVENT_DEVICES_INFOS }

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
     * @returns {Promise<{ip: *, name: *, mac: null}>}
     */
    async deviceInfos(ip){
        F.validateParamIp(ip);
        await this.osPingCommand(ip);
        //we already know it responds to ping, but we need to update the update the os arp table before deviceMAC()
        let r1 = await this.deviceMAC(ip);
        let r2 = await this.deviceName(ip);
        return {
            'name' : r2,
            'ip' : ip,
            'mac' : (r1 ? r1.mac : null),  //mac is null for self scan (not in arp table)
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
            let exe = 'host';
            let flag = '-W='+this.timeout;
            if(this.osType === OS_WINDOWS){
                exe = 'nslookup';
                flag = '-timeout='+this.timeout;
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
     * Ping an ip address with os ping command (slower but usefull to update the os arp table)
     * @param {String} ip
     */
    async osPingCommand(ip) {
        return new Promise((resolve) => {
            F.validateParamIp(ip);
            Ping.sys.probe(ip, (isAlive) => {
                let message = isAlive ? 'ip ' + ip + ' is alive' : 'ip ' + ip + ' is dead';
                if(this.verbose) console.log('message: ' + message);
                resolve(isAlive);
            });
        });
    }


    /**
     * Start the lan scan (Node ICMP Requests) and return the class object
     */
    startScan(objParam){
        F.validateParamIpArray(objParam.ipArrayToScan);
        this.devicesInfosPromises = [];
        this.scannerICMP.start(objParam);
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