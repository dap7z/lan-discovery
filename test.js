'use strict';
const CidrRange = require('cidr-range');


//STRANGE PREVIOUS BUG (FIXED BY require all before any instantiation) :
//const scannerICMP = require('./node_modules_custom/device-discovery/scanner.js')({ type: 'ICMP' });
//scannerICMP.start({ ipArray: tabIP }); //NOK HERE (before require child_process.exec again)
//const LanDiscovery = require('./lan-discovery/index.js');  //child_process.exec conflict ...
//scannerICMP.start({ ipArrayToScan: tabIP });   //OK HERE : pass in session.pingHost() and emit device event.


const LanDiscovery = require('./index.js');
let discovery = new LanDiscovery({ verbose: false, timeout: 60 });

async function test(){

	//Determine tabIP, the ip range array to scan :
	let myInterface = await discovery.getDefaultInterface();
	console.log('------------ TEST getDefaultInterface() -----------------\n', myInterface);
	let tabIP = CidrRange(myInterface.cidr);
	//console.log('------------ TEST IP RANGE -----------------\n', tabIP);
	//+ exclude self/network/broadcast address ?

	console.log('------------ TEST ARP FUNCTIONS -----------------');
	let arr = await discovery.arpTable();
	console.log(arr.length + ' entries in OS arp table :');
	arr.forEach( (row) => console.log(row) );
	await testDeviceIP('64:A2:F9:A9:25:85');
	await testDeviceIP('40:F2:01:5E:74:CA');
	console.log("isMAC test1, true expected -> ", LanDiscovery.isMAC('64:A2:F9:A9:25:85'));
	console.log("isMAC test2, false expected -> ", LanDiscovery.isMAC('NOT:A:MAC'));

	console.log('------------ TEST LAN SCAN -----------------');
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
	discovery.startScan({ ipArrayToScan: tabIP });
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


