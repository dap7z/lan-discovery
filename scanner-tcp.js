'use strict'

const Scanner = require('./scanner');
const { Socket } = require('net')

class ScannerTCP extends Scanner {

    //properties from generic scan class :
    //this.ipArrayToScan
    //this.ipArrayResults

    start({ ipArrayToScan = [], timeout = 3000, port = 1 }) {
        super.start({ ipArrayToScan : ipArrayToScan });

        let pending = 0

        for (let ip of this.ipArrayToScan) {
            pending++
            this.scanHost({ ip, port, timeout }, error => {
                if (!error){
                    this.ipArrayResults.push(ip);
                    this.emit(Scanner.EVENT_RESPONSE, ip)
                }
                if (!--pending){
                    this.emit(Scanner.EVENT_COMPLETE, this.buildScanResult());
                }
            })
        }

        return this
    }

    scanHost({ ip, port, timeout }, callback){
        const socket = new Socket()

        socket.setTimeout(timeout)
        socket.connect({ host: ip, port })
        socket.unref()

        socket.on('error', error =>
            'ECONNREFUSED' === error.code ? callback(false) : callback(true))

        socket.on('timeout', () => {
            callback(true); socket.destroy() })

        socket.on('connect', () => {
            callback(false); socket.destroy() })
    }

}

module.exports = ScannerTCP;

//TODO: TEST IT :80