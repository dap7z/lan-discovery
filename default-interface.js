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
const defaultGateway = require('default-gateway');
const ipaddr = require('ipaddr.js');

function findInterface(gateway) {
	const interfaces = os.networkInterfaces();
	const gatewayIp = ipaddr.parse(gateway);
	let result = {};

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

function promise(family) {
	return defaultGateway[family]().then(result => {
		return findInterface(result.gateway) || null;
	}).catch(() => null);
}

function sync(family) {
	try {
		const result = defaultGateway[family].sync();
		return findInterface(result.gateway) || null;
	} catch (err) {
		return null;
	}
}

module.exports.v6 = () => promise('v6');
module.exports.v4 = () => promise('v4');

module.exports.v6.sync = () => sync('v6');
module.exports.v4.sync = () => sync('v4');
