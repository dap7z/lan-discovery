'use strict'

const Scanner = require('./scanner');
const NetPing = require('net-ping')

class ScannerICMP extends Scanner {

    //properties from generic scan class :
    //this.ipArrayToScan
    //this.ipArrayResults

    /**
     * Start ICMP ping scan
     * @param {Object} params - { ipArrayToScan, timeout, retries, interval }
     * @param {Array} params.ipArrayToScan - Array of IP addresses to ping
     * @param {number} params.timeout - Timeout in milliseconds (default: 3000)
     * @param {number} params.retries - Number of retries (default: 0)
     * @param {number} params.interval - Delay between pings in milliseconds (default: 0)
     *   - 0ms: No delay (all pings sent simultaneously) - original behavior
     *   - 100ms: Occasional use, home LAN (5min for /24)
     *   - 200ms: Production/sensitive (10min) - recommended, zero perceptible impact
     *   - 500ms: Paranoid/critical network
     * @returns {This} Returns this instance for chaining
     */
    start({ ipArrayToScan = [], timeout = 3000, retries = 0, interval = 0 }) {
        super.start({ ipArrayToScan : ipArrayToScan }); //fill this.ipArrayToScan

        const session = NetPing.createSession({ timeout, retries })
        let pending = 0


        // Send pings with interval delay to avoid network saturation
        // ICMP is L3 routable, so routers/firewalls process each packet
        // Spacing prevents burst traffic that could saturate the network
        // /!\ default interval is 0ms, so all pings are sent very close to each other.
        this.ipArrayToScan.forEach((ip, index) => {
            setTimeout(() => {
                pending++
                session.pingHost(ip, error => {
                    if (!error) {
                        this.ipArrayResults.push(ip);
                        this.emit(Scanner.EVENT_RESPONSE, ip)
                    }
                    if (!--pending) {
                        this.emit(Scanner.EVENT_COMPLETE, this.buildScanResult());
                        session.close()
                    }
                })
            }, index * interval)
        })
        

        return this
    }

}

module.exports = ScannerICMP;
