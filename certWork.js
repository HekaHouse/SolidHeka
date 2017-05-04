var cn = 'aron33.heka.house';
var WebCrypto = require("node-webcrypto-ossl");
var fs = require('fs');
var Promise = require('bluebird');
var openssl = require('openssl-wrapper');
var pem2jwk = require('pem-jwk').pem2jwk;
var jwk2pem = require('pem-jwk').jwk2pem;
const opensslAsync = Promise.promisify(openssl.exec);
const password = 'h3kaMu$tR3mainS3cure';
const certHelp = require('./CertificateHelper/bundle.js');
const child_process = require('child_process');
var keyPem;

var cleanPEM = function(pem) {
    var cleaned = pem.replace(/(-----(BEGIN|END) RSA PRIVATE KEY-----|\n)/g, "").replace(/\r?\n|\r/g,'');
    return new Uint8Array(convertStringToArrayBufferView(hex2a(cleaned)));
}

function getCrypto()
{
	return new WebCrypto().subtle;
}

function hex2a(hexx) {
    var hex = hexx.toString();//force conversion
    var str = '';
    for (var i = 0; i < hex.length; i += 2)
        str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    return str;
}

function convertStringToArrayBufferView(str){
    var bytes = new Uint8Array(str.length);
    for (var iii = 0; iii < str.length; iii++) {
        bytes[iii] = str.charCodeAt(iii);
    }

    return bytes;
}

function convertArrayBufferViewtoString(buffer){
    var str = "";
    for (var iii = 0; iii < buffer.byteLength; iii++) {
        str += String.fromCharCode(buffer[iii]);
    }

    return str;
}

var keyPem;

opensslAsync('genrsa', {'out':'ca/intermediate/private/'+cn+'.key.pem','2048': false})
.then((keyed) => {
	console.log('generating CSR from PKCS8');
	return opensslAsync(
		'req', 
		{
			config:'ca/intermediate/openssl.cnf', 
			'key':'ca/intermediate/private/'+cn+'.key.pem', 
			'new':true, 
			'out':'ca/intermediate/csr/'+cn+'.csr.pem', 
			'sha256':true, 
			'subj':'/CN='+cn
		}
	)
})
.then((csr) => {
	console.log('csr returned',csr.toString());
	return opensslAsync(
		'ca', 
		{
			config:'ca/intermediate/openssl.cnf', 
			'in':'ca/intermediate/csr/'+cn+'.csr.pem',
			'out':'ca/intermediate/newcerts/'+cn+'.crt.pem',
			'passin':'file:ca/pass',
			'batch':true
		}
	)
})
.then((crt) =>{

console.log('cert created',crt.toString());
var result = child_process.execSync('openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in ca/intermediate/private/'+cn+'.key.pem -out ca/intermediate/private/'+cn+'.pk8.key.pem');
var keyPem = fs.readFileSync('ca/intermediate/private/'+cn+'.key.pem', 'ascii');
var keyPemPK8 = fs.readFileSync('ca/intermediate/private/'+cn+'.pk8.key.pem', 'ascii');




getCrypto().importKey(
    "jwk",
    pem2jwk(keyPem),
    {   //these are the algorithm options
        name: "RSASSA-PKCS1-v1_5",
        hash: {name: "SHA-256"}
    },
    false, 
    ["sign"] 
)
.catch(function(err){
    console.error(err,'standard');
});



});
