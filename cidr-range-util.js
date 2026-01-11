'use strict';

/**
 * Utility function to replace cidr-range package
 * Generates an array of IP addresses from a CIDR notation
 * Uses netmask package which is already a dependency
 * @param {string} cidr - CIDR notation (e.g., "192.168.1.0/24")
 * @returns {Array<string>} Array of IP addresses in the CIDR range
 */
function cidrRange(cidr) {
	const Netmask = require('netmask').Netmask;
	
	if (!cidr || typeof cidr !== 'string') {
		throw new Error('CIDR must be a non-empty string');
	}
	
	try {
		const block = new Netmask(cidr);
		const ipArray = [];
		
		// Use forEach method from netmask package
		block.forEach((ip) => {
			ipArray.push(ip);
		});
		
		return ipArray;
	} catch (error) {
		throw new Error(`Invalid CIDR: ${error.message}`);
	}
}

module.exports = cidrRange;

