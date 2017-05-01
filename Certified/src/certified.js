
exports.generateCSR = function(keyPair,db,csrStruct) {
	return createPKCS10(keyPair,db,csrStruct);
}

exports.parseCSR = function(csr) {
	return parsePKCS10(csr);
}

exports.verifyCSR = function(csr) {
	return verifyPKCS10(csr);
}

exports.generateRSAKeyPair = function() {
	return Promise.resolve().then(function() { return generateRSASSA_PKCS1_V1_5(); });
}

function generateECDHKeyPair() {

}

//returns promise
function retrieveKeyValue(key) {

}

exports.storeKeyValue = function(db,key,value) {
	var store = new db('certified');
    store.set(key,value, function (err) {if (err) throw err});   
}
