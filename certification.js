var forge = require('node-forge');
var pki = forge.pki;

String.prototype.getBytes = function() {
    var bytes = [];
    for (var i = 0; i < this.length; i++) {
        var charCode = this.charCodeAt(i);
        var cLen = Math.ceil(Math.log(charCode)/Math.log(256));
        for (var j = 0; j < cLen; j++) {
            bytes.push((charCode << (j*8)) & 0xFF);
        }
    }
    return bytes;
}

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

  var md = forge.md.sha256.create();
  md.update(JSON.stringify(certObj));

  var signature = keys.privateKey.sign(md);

  var verified = keys.publicKey.verify(md.digest().getBytes(), signature);
  console.log(verified);


  var signed = forge.util.encode64(signature);
  console.log(signed);
  certObj.signed = signed;

  return certObj;
}





