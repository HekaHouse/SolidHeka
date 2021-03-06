window.pki = require('pkijs');
const compPKI = require('./pki-compiled');
const _ = require('lodash');
window.db = require('idb-kv-store');
window.certified = require('./certified');
const api = require('./api');

function showResult(result) {
	var element = document.createElement('div');
	element.innerHTML = result;
	document.body.appendChild(element);
}

function storeKeys(keyPair) {
	storeKeyValue(db,'public',keyPair.publicKey);
	storeKeyValue(db,'private',keyPair.privateKey);
}

var storeKeyValue = function(db,key,value) {
	var store = new db('certified');
    store.set(key,value, function (err) {if (err) throw err});   
}

window.storeKeys = storeKeys;
window.storeKeyValue = storeKeyValue;
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

window.definePersonaCSR = definePersonaCSR;

// certified.generateRSAKeyPair()
// 		.then(function(keyPair){			
// 			storeKeys(keyPair);		
// 			return certified.generateCSR(keyPair,db,definePersonaCSR());
// 		})
// 		.then(function(csr){			
// 			certified.storeKeyValue(db,'csr',csr);				
// 			certified.verifyCSR(csr)
// 			.then(function(verified){
// 				console.log(verified);
// 				if (verified) {
// 					certified.parseCSR(csr)
// 					.then(function(csrStruct){
// 						return JSON.stringify(csrStruct);
// 					})
// 					.then(function(csrStr){
// 						document.querySelector("#spkacWebID").value = csrStr;
// 					});
// 				}
// 			});			
// 		});


		 
