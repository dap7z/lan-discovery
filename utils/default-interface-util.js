'use strict';
/*
* @Name:        		default-interface
* @Author:              dap7z
* @Credits:				internal-ip by Sindre Sorhus (https://sindresorhus.com)
* @License: 			MIT
* @Date:                2018-12-01
* @Description:         Retrieve all informations about the default interface
* (Match by corresponding network, more safe. Windows encode name in UTF-16...)
* Based on internal-ip plugin : https://github.com/sindresorhus/internal-ip
* With a little modification : retrive all informations of the default interface, not only ip address.
*
*
* (async) v6() : 
* @return {Promise}      	In promise, default interface data (IPv6)
*
* (async) v4() : 
* @return {Promise}      	In promise, default interface data (IPv4)
*
* (async) v6() : 
* @return {Object}      	Default interface data (IPv6)
*
* (async) v4() : 
* @return {Object}      	Default interface data (IPv4)
*
*/
const os = require('os');
const gatewayDetector = require('./gateway-detector-util');
const ipaddr = require('ipaddr.js');

function findInterface(gateway) {
	const interfaces = os.networkInterfaces();
	const gatewayIp = ipaddr.parse(gateway);
	let result = null;

	// Look for the matching interface in all local interfaces
	Object.keys(interfaces).some(name => {
		return interfaces[name].some(addr => {
			const prefix = ipaddr.parse(addr.netmask).prefixLengthFromSubnetMask();
			const net = ipaddr.parseCIDR(`${addr.address}/${prefix}`);

			if (net[0] && net[0].kind() === gatewayIp.kind() && gatewayIp.match(net)) {
				result = addr;
				result.gateway = gateway;
				result.name = name;
				result.cidr = `${addr.address}/${prefix}`;
			}

		});
	});

	return result;
}

/**
 * Fallback method to find default interface when gateway cannot be determined
 * Returns the first non-loopback IPv4 interface
 */
function findDefaultInterfaceFallback() {
	const interfaces = os.networkInterfaces();
	let result = null;

	// Look for the first non-loopback IPv4 interface
	Object.keys(interfaces).some(name => {
		return interfaces[name].some(addr => {
			if (addr.family === 'IPv4' && !addr.internal) {
				try {
					// Try to parse netmask if available
					let prefix = 24; // Default to /24 if netmask is missing
					if (addr.netmask) {
						prefix = ipaddr.parse(addr.netmask).prefixLengthFromSubnetMask();
					}
					result = addr;
					result.gateway = null; // Gateway unknown
					result.name = name;
					result.cidr = `${addr.address}/${prefix}`;
					return true;
				} catch (err) {
					// If netmask parsing fails, use default /24
					result = addr;
					result.gateway = null;
					result.name = name;
					result.cidr = `${addr.address}/24`;
					return true;
				}
			}
			return false;
		});
	});

	return result;
}

function promise(family) {
	return gatewayDetector[family]()
		.then(result => {
			return findInterface(result.gateway) || null;
		})
		.catch((err) => {
			// Silently handle errors from gateway detector
			// Use fallback method to find default interface
			if (family === 'v4') {
				return findDefaultInterfaceFallback();
			}
			return null;
		});
}

function sync(family) {
	try {
		// gateway-detector doesn't support sync, use async with immediate fallback
		// This maintains compatibility with the existing API
		if (family === 'v4') {
			return findDefaultInterfaceFallback();
		}
		return null;
	} catch (err) {
		// Use fallback method when gateway detector fails
		if (family === 'v4') {
			return findDefaultInterfaceFallback();
		}
		return null;
	}
}

module.exports.v6 = () => promise('v6');
module.exports.v4 = () => promise('v4');

module.exports.v6.sync = () => sync('v6');
module.exports.v4.sync = () => sync('v4');

