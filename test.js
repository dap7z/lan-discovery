'use strict';
const LanDiscovery = require('./index.js');
const CidrRange = LanDiscovery.cidrRange;

let discovery = new LanDiscovery({ verbose: false, timeout: 60 });

async function test(){



	//Determine tabIP, the ip range array to scan :
	let myInterface = await discovery.getDefaultInterface();
	let tabIP = CidrRange(myInterface.cidr);

	/*
	console.log('------------ TEST getDefaultInterface() -----------------\n', myInterface);
	//console.log('------------ TEST IP RANGE -----------------\n', tabIP);
	//+ exclude self/network/broadcast address ?

	console.log('----------------- TEST ARP FUNCTIONS --------------------');
	let arr = await discovery.arpTable();
	console.log(arr.length + ' entries in OS arp table :');
	arr.forEach( (row) => console.log(row) );
	await testDeviceIP('64:A2:F9:A9:25:85');
	await testDeviceIP('40:F2:01:5E:74:CA');
	console.log("isMAC test1, true expected -> ", LanDiscovery.isMAC('64:A2:F9:A9:25:85'));
	console.log("isMAC test2, false expected -> ", LanDiscovery.isMAC('NOT:A:MAC'));
	*/

	/*
	// DONT REQUIRE ROOT/ADMIN RIGTHS BUT IMPACT ON THE NETWORK WITHOUT INTERVAL BETWEEN PINGS
	console.log('-------------- TEST LAN SCAN --(PING ONLY)---------------');
	discovery.on(LanDiscovery.EVENT_SCAN_RESPONSE, (ip) => {
		console.log('--> event '+ LanDiscovery.EVENT_SCAN_RESPONSE +' :', ip);
	}).on(LanDiscovery.EVENT_DEVICE_INFOS, (device) => {
		console.log('--> event '+ LanDiscovery.EVENT_DEVICE_INFOS +' :\n', device);
	}).on(LanDiscovery.EVENT_SCAN_COMPLETE, (data) => {
		console.log('--> event '+ LanDiscovery.EVENT_SCAN_COMPLETE +' :\n', data);
		testDeviceName('192.168.1.1');
	}).on(LanDiscovery.EVENT_DEVICES_INFOS, (data) => {
        console.log('--> event '+ LanDiscovery.EVENT_DEVICES_INFOS +' :\n', data);
    });
	//await discovery.startScan({ ipArrayToScan: tabIP });
	await discovery.startScan({ ipArrayToScan: tabIP, interval: 100 }); // ping only
	//console.log('---------------------------------------------------------');
	*/
	
	
	// LOW IMPACT ON THE NETWORK BUT REQUIRE ROOT/ADMIN RIGTHS
	console.log('---------- TEST HYBRID SCAN (ARP + PING) ----------------');
	discovery.on(LanDiscovery.EVENT_ARP_RESPONSE, (device) => {
		console.log('HYBRID-SCAN--> ARP discovered:', device.ip, device.mac);
	}).on(LanDiscovery.EVENT_ARP_COMPLETE, (data) => {
		console.log('HYBRID-SCAN--> ARP scan complete:', data);
	}).on(LanDiscovery.EVENT_SCAN_RESPONSE, (ip) => {
		console.log('HYBRID-SCAN--> Ping response from:', ip);
	}).on(LanDiscovery.EVENT_DEVICE_INFOS, (device) => {
		console.log('HYBRID-SCAN--> Device info:', device);
	}).on(LanDiscovery.EVENT_SCAN_COMPLETE, (data) => {
		console.log('HYBRID-SCAN--> Ping scan complete:', data);
	}).on(LanDiscovery.EVENT_DEVICES_INFOS, (devices) => {
		console.log('HYBRID-SCAN--> All devices info:', devices.length, 'devices found');
		devices.forEach((device, index) => {
			console.log(`  ${index + 1}. ${device.ip} - ${device.mac || 'N/A'} - ${device.name || 'N/A'}`);
		});
	});
	// Start hybrid scan: ARP broadcast + ping on discovered IPs
	await discovery.startHybridScan({ 
		networkInterface: myInterface,
	    timeout: 3000,
		interval: 100,
		verbose: false
	});
	console.log('---------------------------------------------------------');
	

}

async function testDeviceIP(macTest){
	console.log(macTest, await discovery.deviceIP(macTest));
}

async function testDeviceName(ipTest){
    let name = await discovery.deviceName(ipTest);
    console.log('------------ TEST DEVICE NAME -----------------');
	console.log(ipTest + " name is :", name);
}


test();


