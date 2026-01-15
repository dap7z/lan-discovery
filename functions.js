'use strict'

const Net = require('net');

class F {

    /**
     * Checks parameter ip
     * @param ip An ipv4 string
     */
    static validateParamIp(ip){
        if(!F.isIP(ip)){
            console.error('invalid ip : "', ip, '"');
            throw new Error('invalid ip');
        }
    }

    /**
     * Checks parameter ipArray
     * @param ipArray An array of ip (string)
     */
    static validateParamIpArray(ipArray){
        if (!Array.isArray(ipArray)){
            let msg = 'ipArray must be an array of IP addresses';
            console.error(msg + ', got :', ipArray);
            throw new Error(msg);
        }
        if (!ipArray.length) throw new Error('ipArray must not be empty');
        ipArray.forEach((ip) => {
            F.validateParamIp(ip);
        });
    }

    /**
     * Normalizes a MAC address so that `-` is
     * replaced `:` and is converted to lower case
     *
     * Example: `04-A1-51-1B-12-92` => `04:a1:51:1b:12:92`
     * @param mac The MAC Address to normalize
     */
    static normalizeMAC(mac) {
        return mac.replace(/\-/g, ':').toUpperCase();
    }

    /**
     * Checks if a MAC address is valid
     * @param mac The MAC address to validate
     */
    static isMAC(mac) {
        return /^([0-9A-F]{2}[:-]){5}([0-9A-F]{2})$/i.test(mac);
    }

    /**
     * Checks if a IP address is valid
     * @param ip The IP address to validate
     */
    static isIP(ip) {
        return Net.isIP(ip);
    }

}

module.exports = F;
