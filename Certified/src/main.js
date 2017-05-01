const compPKI = require('./pki-compiled');
const _ = require('lodash');
const db = require('idb-kv-store');
const certified = require('./certified');
const api = require('./api');

function showResult(result) {
	var element = document.createElement('div');
	element.innerHTML = result;
	document.body.appendChild(element);
}

function storeKeys(keyPair) {
	certified.storeKeyValue(db,'public',keyPair.publicKey);
	certified.storeKeyValue(db,'private',keyPair.privateKey);
}

function definePersonaCSR(
	persona='o',
	host='heka.house',
	instance='default',
	namespace='private:services',
	locality='Columbus',
	state='Ohio',
	country='US') {
	return {
		'CN': persona+'.'+host,
		'O' : host,
		'OU': 'WebId:persona',
		'L' : locality,
		'S' : state,
		'C' : country,
		'GN': instance,
		'SN': namespace
	};
}


		 
