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

certified
.generateRSAKeyPair()
.then(function(keyPair){			
	storeKeys(keyPair);		
	return certified.generateCSR(keyPair,db,definePersonaCSR());
})
.then(function(csr){			
	certified.storeKeyValue(db,'csr',csr);				
	certified.verifyCSR(csr)
	.then(function(verified){
		console.log(verified);
		if (verified) {
			certified.parseCSR(csr)
			.then(function(csrStruct){
				return JSON.stringify(csrStruct);
			})
			.then(showResult);
		}
	});			
});
		 
api.requestPersona('aron').then(function(available){
	if (available === '404') {
		console.log('it worked!');
	} else {
		console.log('unavailable',available);
	}
})