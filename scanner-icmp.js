'use strict'

const Scanner = require('./scanner');
const NetPing = require('net-ping')

class ScannerICMP extends Scanner {

    //properties from generic scan class :
    //this.ipArrayToScan
    //this.ipArrayResults

    start({ ipArrayToScan = [], timeout = 3000, retries = 0 }) {
        super.start({ ipArrayToScan : ipArrayToScan }); //fill this.ipArrayToScan

        const session = NetPing.createSession({ timeout, retries })
        let pending = 0

        for (let ip of this.ipArrayToScan) {
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
        }

        return this
    }

}

module.exports = ScannerICMP;
