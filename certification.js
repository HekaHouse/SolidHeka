var forge = require('node-forge');
var pki = forge.pki;



exports.generate = function(username,csrpem) {
  var csr = forge.pki.certificationRequestFromPem(csrpem);
  // generate a keypair and create an X.509v3 certificate
  var keys = pki.rsa.generateKeyPair(2048);
  var cert = pki.createCertificate();
  cert.publicKey = csr.publicKey;
  // alternatively set public key from a csr
  //cert.publicKey = csr.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
  var attrs = [{
    name: 'commonName',
    value: username+'.heka.house'
  }, {
    name: 'countryName',
    value: 'US'
  }, {
    shortName: 'ST',
    value: 'Ohio'
  }, {
    name: 'localityName',
    value: 'Columbus'
  }, {
    name: 'organizationName',
    value: 'Heka.House'
  }, {
    shortName: 'OU',
    value: 'Solid'
  }];
  cert.setSubject(attrs);
  // alternatively set subject from a csr
  //cert.setSubject(csr.subject.attributes);
  cert.setIssuer(attrs);
  cert.setExtensions([{
    name: 'basicConstraints',
    cA: true
  }, {
    name: 'keyUsage',
    keyCertSign: true,
    digitalSignature: true,
    nonRepudiation: true,
    keyEncipherment: true,
    dataEncipherment: true
  }, {
    name: 'extKeyUsage',
    serverAuth: true,
    clientAuth: true,
    codeSigning: true,
    emailProtection: true,
    timeStamping: true
  }, {
    name: 'nsCertType',
    client: true,
    server: true,
    email: true,
    objsign: true,
    sslCA: true,
    emailCA: true,
    objCA: true
  }, {
    name: 'subjectAltName',
    altNames: [{
      type: 6, // URI
      value: 'https://'+username+'.heka.house/webid#me'
    }, {
      type: 7, // IP
      ip: '104.196.225.39'
    }]
  }, {
    name: 'subjectKeyIdentifier'
  }]);

  cert.sign(keys.privateKey);

  // convert a Forge certificate to PEM
  var certifiedpem = pki.certificateToPem(cert);


  var enc_priv = pki.encryptRsaPrivateKey(keys.privateKey, 'password');
  var pub = pki.publicKeyToPem(keys.publicKey);

  var certObj = {'keys':{'public':pub,'private':enc_priv},'request':csrpem,'cert':certifiedpem};

  var bin = toBin(JSON.stringify(certObj));
  var signature = keys.privateKey.sign(bin);

  var verified = keys.publicKey.verify(bin, signature);
  console.log(verified);


  var signed = createHexString(signature);
  console.log(signed);
  certObj.signed = signed;

  return certObj;
}

function toBin(str){
 var st,i,j,d;
 var arr = [];
 var len = str.length;
 for (i = 1; i<=len; i++){
                //reverse so its like a stack
  d = str.charCodeAt(len-i);
  for (j = 0; j < 8; j++) {
   st = d&#37;2 == '0' ? "class='zero'" : "" 
   arr.push(d%2);
   d = Math.floor(d/2);
  }
 }
        //reverse all bits again.
 return arr.reverse().join("");
}

function parseHexString(str) { 
    var result = [];
    while (str.length >= 8) { 
        result.push(parseInt(str.substring(0, 8), 16));

        str = str.substring(8, str.length);
    }

    return result;
}

function createHexString(arr) {
    var result = "";
    var z;

    for (var i = 0; i < arr.length; i++) {
        var str = arr[i].toString(16);

        z = 8 - str.length + 1;
        str = Array(z).join("0") + str;

        result += str;
    }

    return result;
}

