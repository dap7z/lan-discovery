'use strict'

const EventEmitter = require('events')
const F = require('./functions');

//CONSTANTS
const EVENT_RESPONSE = 'response';
const EVENT_COMPLETE = 'complete';

class Scanner extends EventEmitter {

    //define events emitted by child class :
    static get EVENT_RESPONSE(){ return EVENT_RESPONSE }
    static get EVENT_COMPLETE(){ return EVENT_COMPLETE }

    constructor() {
        super()
        //init variables :
        this.dateStart = null;
        this.ipArrayToScan = null;
        this.ipArrayResults = null;
        //this.excludeSelf = false; // whether to exclude the device the discovery is run on
    }

    start({ ipArrayToScan = [] }) {
        // We check the ipArrayToScan parameter, except if we are ScannerARP and working with MAC addresses ;)
        if (this.constructor.name !== 'ScannerARP') {
            F.validateParamIpArray(ipArrayToScan)
        }
        this.ipArrayToScan = ipArrayToScan;
        this.ipArrayResults = [];
        this.timerStart()
    }


    timerStart() {
        this.dateStart = new Date()
    }

    timerDiff() {
        //get execution time :
        return new Date() - this.dateStart
    }

    buildScanResult(){
        let scanCount = this.ipArrayToScan ? this.ipArrayToScan.length : null;
        if (this.constructor.name !== 'ScannerARP') {
            scanCount = this.ipArrayResults.length;
        }
        
        let executionTimeMS = this.timerDiff()
        return {
            ipArray : this.ipArrayResults,
            scanCount : scanCount,
            scanTimeMS : executionTimeMS,
            scanAverageMS : Math.round(executionTimeMS/scanCount),
        };
    }

}

module.exports = Scanner;
