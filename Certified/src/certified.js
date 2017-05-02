
var generateCSR = function(keyPair,db,csrStruct) {
	return createPKCS10(keyPair,db,csrStruct);
}

exports.parseCSR = function(csr) {
	return parsePKCS10(csr);
}

exports.verifyCSR = function(csr) {
	return verifyPKCS10(csr);
}

var generateRSAKeyPair = function() {
	return Promise.resolve().then(function() { return generateRSASSA_PKCS1_V1_5(); });
}

function generateECDHKeyPair() {

}

//returns promise
function retrieveKeyValue(key) {

}



window.generateCSR = generateCSR;
window.generateRSAKeyPair = generateRSAKeyPair;