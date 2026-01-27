'use strict';

/**
 * Simple gateway detector for multiple platforms
 * Inspired by network-default-gateway
 * Supports: Windows (PowerShell), Linux, macOS
 */

const os = require('os');
const { exec } = require('child_process');
const { promisify } = require('util');

const execAsync = promisify(exec);

const platform = os.platform();

/**
 * Get default gateway for IPv4 on Windows using PowerShell
 */
async function getGatewayWindowsV4() {
	// Use PowerShell Get-NetRoute (works on Windows 11 without wmic)
	// This is the primary method used by network-default-gateway
	const { stdout } = await execAsync(
		'powershell -Command "Get-NetRoute -DestinationPrefix 0.0.0.0/0 -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty NextHop"'
	);
	const gateway = stdout.trim();
	if (gateway && gateway !== '') {
		return { gateway };
	}
	
	throw new Error('Unable to determine default gateway on Windows');
}

/**
 * Get default gateway for IPv6 on Windows using PowerShell
 */
async function getGatewayWindowsV6() {
	try {
		const { stdout } = await execAsync(
			'powershell -Command "Get-NetRoute -DestinationPrefix ::/0 -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty NextHop"'
		);
		const gateway = stdout.trim();
		if (gateway && gateway !== '') {
			return { gateway };
		}
	} catch (err) {
		// PowerShell failed
	}

	throw new Error('Unable to determine default gateway IPv6 on Windows');
}

/**
 * Get default gateway for IPv4 on Linux
 */
async function getGatewayLinuxV4() {
	try {
		// Try 'ip route' first (modern method)
		const { stdout } = await execAsync('ip route show default');
		const match = stdout.match(/default via (\S+)/);
		if (match) {
			return { gateway: match[1] };
		}
	} catch (err) {
		// ip route failed, try route command
	}

	try {
		// Fallback: use 'route' command
		const { stdout } = await execAsync('route -n');
		const lines = stdout.split('\n');
		for (const line of lines) {
			if (line.startsWith('0.0.0.0')) {
				const parts = line.trim().split(/\s+/);
				if (parts.length >= 2 && parts[1] !== '0.0.0.0') {
					return { gateway: parts[1] };
				}
			}
		}
	} catch (err) {
		// route also failed
	}

	throw new Error('Unable to determine default gateway on Linux');
}

/**
 * Get default gateway for IPv6 on Linux
 */
async function getGatewayLinuxV6() {
	try {
		const { stdout } = await execAsync('ip -6 route show default');
		const match = stdout.match(/default via (\S+)/);
		if (match) {
			return { gateway: match[1] };
		}
	} catch (err) {
		// ip route failed
	}

	throw new Error('Unable to determine default gateway IPv6 on Linux');
}

/**
 * Get default gateway for IPv4 on macOS
 */
async function getGatewayMacOSV4() {
	try {
		const { stdout } = await execAsync('route -n get default');
		const match = stdout.match(/gateway:\s*(\S+)/);
		if (match) {
			return { gateway: match[1] };
		}
	} catch (err) {
		// route failed
	}

	throw new Error('Unable to determine default gateway on macOS');
}

/**
 * Get default gateway for IPv6 on macOS
 */
async function getGatewayMacOSV6() {
	try {
		const { stdout } = await execAsync('route -n get -inet6 default');
		const match = stdout.match(/gateway:\s*(\S+)/);
		if (match) {
			return { gateway: match[1] };
		}
	} catch (err) {
		// route failed
	}

	throw new Error('Unable to determine default gateway IPv6 on macOS');
}

/**
 * Get default gateway (async)
 * @param {string} family - 'v4' or 'v6'
 * @returns {Promise<{gateway: string}>}
 */
async function getGateway(family) {
	const isV4 = family === 'v4';
	
	if (platform === 'win32') {
		return isV4 ? getGatewayWindowsV4() : getGatewayWindowsV6();
	} else if (platform === 'linux') {
		return isV4 ? getGatewayLinuxV4() : getGatewayLinuxV6();
	} else if (platform === 'darwin') {
		return isV4 ? getGatewayMacOSV4() : getGatewayMacOSV6();
	} else {
		throw new Error(`Unsupported platform: ${platform}`);
	}
}

/**
 * Get default gateway (sync) - not supported, throws error
 * @param {string} family - 'v4' or 'v6'
 * @returns {Object}
 */
function getGatewaySync(family) {
	throw new Error('Sync method not supported. Use async method instead.');
}

module.exports = {
	v4: () => getGateway('v4'),
	v6: () => getGateway('v6'),
	v4Sync: () => getGatewaySync('v4'),
	v6Sync: () => getGatewaySync('v6')
};

