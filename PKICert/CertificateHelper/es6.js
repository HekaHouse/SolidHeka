import * as asn1js from "asn1js";
import { arrayBufferToString, stringToArrayBuffer, toBase64, fromBase64, bufferToHexCodes } from "pvutils";
import { getCrypto, getAlgorithmParameters, setEngine } from "../../src/common";

import Certificate from "../../src/Certificate";
import CertificationRequest from "../../src/CertificationRequest";
import CertificateChainValidationEngine from "../../src/CertificateChainValidationEngine";
import CertificateRevocationList from "../../src/CertificateRevocationList";

import AttributeTypeAndValue from "../../src/AttributeTypeAndValue";
import Attribute from "../../src/Attribute";
import Extension from "../../src/Extension";
import Extensions from "../../src/Extensions";
import RSAPublicKey from "../../src/RSAPublicKey";
import BasicConstraints from "../../src/BasicConstraints";

//*********************************************************************************
let pkcs10Buffer = new ArrayBuffer(0);

let certificateBuffer = new ArrayBuffer(0); // ArrayBuffer with loaded or created CERT
let privateKeyBuffer = new ArrayBuffer(0);
let trustedCertificates = []; // Array of root certificates from "CA Bundle"
const intermadiateCertificates = []; // Array of intermediate certificates
const crls = []; // Array of CRLs for all certificates (trusted + intermediate)

let hashAlg = "SHA-1";
let signAlg = "RSASSA-PKCS1-V1_5";
//*********************************************************************************
function formatPEM(pemString)
{
	/// <summary>Format string in order to have each line with length equal to 63</summary>
	/// <param name="pemString" type="String">String to format</param>
	
	const stringLength = pemString.length;
	let resultString = "";
	
	for(let i = 0, count = 0; i < stringLength; i++, count++)
	{
		if(count > 63)
		{
			resultString = `${resultString}\r\n`;
			count = 0;
		}
		
		resultString = `${resultString}${pemString[i]}`;
	}
	
	return resultString;
}
//*********************************************************************************
//region Create PKCS#10
//*********************************************************************************
function createPKCS10Internal()
{
	//region Initial variables
	let sequence = Promise.resolve();
	
	const pkcs10 = new CertificationRequest();
	
	let publicKey;
	let privateKey;
	//endregion
	
	//region Get a "crypto" extension
	const crypto = getCrypto();
	if(typeof crypto === "undefined")
		return Promise.reject("No WebCrypto extension found");
	//endregion
	
	//region Put a static values
	pkcs10.version = 0;
	pkcs10.subject.typesAndValues.push(new AttributeTypeAndValue({
		type: "2.5.4.6",
		value: new asn1js.PrintableString({ value: "RU" })
	}));
	pkcs10.subject.typesAndValues.push(new AttributeTypeAndValue({
		type: "2.5.4.3",
		value: new asn1js.Utf8String({ value: "Simple test (простой тест)" })
	}));
	
	pkcs10.attributes = [];
	//endregion
	
	//region Create a new key pair
	sequence = sequence.then(() =>
		{
			//region Get default algorithm parameters for key generation
			const algorithm = getAlgorithmParameters(signAlg, "generatekey");
			if("hash" in algorithm.algorithm)
				algorithm.algorithm.hash.name = hashAlg;
			//endregion
			
			return crypto.generateKey(algorithm.algorithm, true, algorithm.usages);
		}
	);
	//endregion
	
	//region Store new key in an interim variables
	sequence = sequence.then(keyPair =>
		{
			publicKey = keyPair.publicKey;
			privateKey = keyPair.privateKey;
		},
		error => Promise.reject((`Error during key generation: ${error}`))
	);
	//endregion
	
	//region Exporting public key into "subjectPublicKeyInfo" value of PKCS#10
	sequence = sequence.then(() => pkcs10.subjectPublicKeyInfo.importKey(publicKey));
	//endregion
	
	//region SubjectKeyIdentifier
	sequence = sequence.then(() => crypto.digest({ name: "SHA-1" }, pkcs10.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHex))
		.then(result =>
			{
				pkcs10.attributes.push(new Attribute({
					type: "1.2.840.113549.1.9.14", // pkcs-9-at-extensionRequest
					values: [(new Extensions({
						extensions: [
							new Extension({
								extnID: "2.5.29.14",
								critical: false,
								extnValue: (new asn1js.OctetString({ valueHex: result })).toBER(false)
							})
						]
					})).toSchema()]
				}));
			}
		);
	//endregion
	
	//region Signing final PKCS#10 request
	sequence = sequence.then(() => pkcs10.sign(privateKey, hashAlg), error => Promise.reject(`Error during exporting public key: ${error}`));
	//endregion
	
	return sequence.then(() =>
	{
		pkcs10Buffer = pkcs10.toSchema().toBER(false);
		
	}, error => Promise.reject(`Error signing PKCS#10: ${error}`));
}
//*********************************************************************************
function createPKCS10()
{
	return Promise.resolve().then(() => createPKCS10Internal()).then(() =>
	{
		let resultString = "-----BEGIN CERTIFICATE REQUEST-----\r\n";
		resultString = `${resultString}${formatPEM(toBase64(arrayBufferToString(pkcs10Buffer)))}`;
		resultString = `${resultString}\r\n-----END CERTIFICATE REQUEST-----\r\n`;
		
		document.getElementById("pem-text-block").value = resultString;
		
		parsePKCS10();
	});
}
//*********************************************************************************
//endregion
//*********************************************************************************
//region Parse existing PKCS#10
//*********************************************************************************
function parsePKCS10()
{
	//region Initial activities
	document.getElementById("pkcs10-subject").innerHTML = "";
	document.getElementById("pkcs10-exten").innerHTML = "";
	
	document.getElementById("pkcs10-data-block").style.display = "none";
	document.getElementById("pkcs10-attributes").style.display = "none";
	//endregion
	
	//region Decode existing PKCS#10
	const stringPEM = document.getElementById("pem-text-block").value.replace(/(-----(BEGIN|END) CERTIFICATE REQUEST-----|\n)/g, "");
	
	const asn1 = asn1js.fromBER(stringToArrayBuffer(fromBase64((stringPEM))));
	const pkcs10 = new CertificationRequest({ schema: asn1.result });
	//endregion
	
	//region Parse and display information about "subject"
	const typemap = {
		"2.5.4.6": "C",
		"2.5.4.11": "OU",
		"2.5.4.10": "O",
		"2.5.4.3": "CN",
		"2.5.4.7": "L",
		"2.5.4.8": "S",
		"2.5.4.12": "T",
		"2.5.4.42": "GN",
		"2.5.4.43": "I",
		"2.5.4.4": "SN",
		"1.2.840.113549.1.9.1": "E-mail"
	};
	
	for(let i = 0; i < pkcs10.subject.typesAndValues.length; i++)
	{
		let typeval = typemap[pkcs10.subject.typesAndValues[i].type];
		if(typeof typeval === "undefined")
			typeval = pkcs10.subject.typesAndValues[i].type;
		
		const subjval = pkcs10.subject.typesAndValues[i].value.valueBlock.value;
		const ulrow = `<li><p><span>${typeval}</span> ${subjval}</p></li>`;
		
		document.getElementById("pkcs10-subject").innerHTML = document.getElementById("pkcs10-subject").innerHTML + ulrow;
		if(typeval === "CN")
			document.getElementById("pkcs10-subject-cn").innerHTML = subjval;
	}
	//endregion
	
	//region Put information about public key size
	let publicKeySize = "< unknown >";
	
	if(pkcs10.subjectPublicKeyInfo.algorithm.algorithmId.indexOf("1.2.840.113549") !== (-1))
	{
		const asn1PublicKey = asn1js.fromBER(pkcs10.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHex);
		const rsaPublicKeySimple = new RSAPublicKey({ schema: asn1PublicKey.result });
		const modulusView = new Uint8Array(rsaPublicKeySimple.modulus.valueBlock.valueHex);
		let modulusBitLength = 0;
		
		if(modulusView[0] === 0x00)
			modulusBitLength = (rsaPublicKeySimple.modulus.valueBlock.valueHex.byteLength - 1) * 8;
		else
			modulusBitLength = rsaPublicKeySimple.modulus.valueBlock.valueHex.byteLength * 8;
		
		publicKeySize = modulusBitLength.toString();
	}
	
	document.getElementById("keysize").innerHTML = publicKeySize;
	//endregion
	
	//region Put information about signature algorithm
	const algomap = {
		"1.2.840.113549.1.1.2": "MD2 with RSA",
		"1.2.840.113549.1.1.4": "MD5 with RSA",
		"1.2.840.10040.4.3": "SHA1 with DSA",
		"1.2.840.10045.4.1": "SHA1 with ECDSA",
		"1.2.840.10045.4.3.2": "SHA256 with ECDSA",
		"1.2.840.10045.4.3.3": "SHA384 with ECDSA",
		"1.2.840.10045.4.3.4": "SHA512 with ECDSA",
		"1.2.840.113549.1.1.10": "RSA-PSS",
		"1.2.840.113549.1.1.5": "SHA1 with RSA",
		"1.2.840.113549.1.1.14": "SHA224 with RSA",
		"1.2.840.113549.1.1.11": "SHA256 with RSA",
		"1.2.840.113549.1.1.12": "SHA384 with RSA",
		"1.2.840.113549.1.1.13": "SHA512 with RSA"
	};
	let signatureAlgorithm = algomap[pkcs10.signatureAlgorithm.algorithmId];
	if(typeof signatureAlgorithm === "undefined")
		signatureAlgorithm = pkcs10.signatureAlgorithm.algorithmId;
	else
		signatureAlgorithm = `${signatureAlgorithm} (${pkcs10.signatureAlgorithm.algorithmId})`;
	
	document.getElementById("sig-algo").innerHTML = signatureAlgorithm;
	//endregion
	
	//region Put information about PKCS#10 attributes
	if("attributes" in pkcs10)
	{
		for(let i = 0; i < pkcs10.attributes.length; i++)
		{
			const typeval = pkcs10.attributes[i].type;
			let subjval = "";
			
			for(let j = 0; j < pkcs10.attributes[i].values.length; j++)
			{
				if((pkcs10.attributes[i].values[j] instanceof asn1js.Utf8String) ||
					(pkcs10.attributes[i].values[j] instanceof asn1js.BmpString) ||
					(pkcs10.attributes[i].values[j] instanceof asn1js.UniversalString) ||
					(pkcs10.attributes[i].values[j] instanceof asn1js.NumericString) ||
					(pkcs10.attributes[i].values[j] instanceof asn1js.PrintableString) ||
					(pkcs10.attributes[i].values[j] instanceof asn1js.TeletexString) ||
					(pkcs10.attributes[i].values[j] instanceof asn1js.VideotexString) ||
					(pkcs10.attributes[i].values[j] instanceof asn1js.IA5String) ||
					(pkcs10.attributes[i].values[j] instanceof asn1js.GraphicString) ||
					(pkcs10.attributes[i].values[j] instanceof asn1js.VisibleString) ||
					(pkcs10.attributes[i].values[j] instanceof asn1js.GeneralString) ||
					(pkcs10.attributes[i].values[j] instanceof asn1js.CharacterString))
				{
					subjval = subjval + ((subjval.length === 0) ? "" : ";") + pkcs10.attributes[i].values[j].valueBlock.value;
				}
				else
					subjval = subjval + ((subjval.length === 0) ? "" : ";") + pkcs10.attributes[i].values[j].constructor.blockName();
			}
			
			const ulrow = `<li><p><span>${typeval}</span> ${subjval}</p></li>`;
			document.getElementById("pkcs10-exten").innerHTML = document.getElementById("pkcs10-exten").innerHTML + ulrow;
		}
		
		document.getElementById("pkcs10-attributes").style.display = "block";
	}
	//endregion
	
	document.getElementById("pkcs10-data-block").style.display = "block";
}
//*********************************************************************************
//endregion
//*********************************************************************************
//region Verify existing PKCS#10
//*********************************************************************************
function verifyPKCS10Internal()
{
	//region Decode existing PKCS#10
	const asn1 = asn1js.fromBER(pkcs10Buffer);
	const pkcs10 = new CertificationRequest({ schema: asn1.result });
	//endregion
	
	//region Verify PKCS#10
	return pkcs10.verify();
	//endregion
}
//*********************************************************************************
function verifyPKCS10()
{
	return Promise.resolve().then(() =>
	{
		pkcs10Buffer = stringToArrayBuffer(fromBase64(document.getElementById("pem-text-block").value.replace(/(-----(BEGIN|END) CERTIFICATE REQUEST-----|\n)/g, "")));
	}).then(() => verifyPKCS10Internal()).then(result =>
	{
		alert(`Verification passed: ${result}`);
	}, error =>
	{
		alert(`Error during verification: ${error}`);
	});
}
//*********************************************************************************
//endregion
//*********************************************************************************

//*********************************************************************************
function parseCertificate()
{
	//region Initial check
	if(certificateBuffer.byteLength === 0)
	{
		alert("Nothing to parse!");
		return;
	}
	//endregion
	
	//region Initial activities
	document.getElementById("cert-extn-div").style.display = "none";
	
	const issuerTable = document.getElementById("cert-issuer-table");
	while(issuerTable.rows.length > 1)
		issuerTable.deleteRow(issuerTable.rows.length - 1);
	
	const subjectTable = document.getElementById("cert-subject-table");
	while(subjectTable.rows.length > 1)
		subjectTable.deleteRow(subjectTable.rows.length - 1);
	
	const extensionTable = document.getElementById("cert-extn-table");
	while(extensionTable.rows.length > 1)
		extensionTable.deleteRow(extensionTable.rows.length - 1);
	//endregion
	
	//region Decode existing X.509 certificate
	const asn1 = asn1js.fromBER(certificateBuffer);
	const certificate = new Certificate({ schema: asn1.result });
	//endregion
	
	//region Put information about X.509 certificate issuer
	const rdnmap = {
		"2.5.4.6": "C",
		"2.5.4.10": "OU",
		"2.5.4.11": "O",
		"2.5.4.3": "CN",
		"2.5.4.7": "L",
		"2.5.4.8": "S",
		"2.5.4.12": "T",
		"2.5.4.42": "GN",
		"2.5.4.43": "I",
		"2.5.4.4": "SN",
		"1.2.840.113549.1.9.1": "E-mail"
	};
	
	for(const typeAndValue of certificate.issuer.typesAndValues)
	{
		let typeval = rdnmap[typeAndValue.type];
		if(typeof typeval === "undefined")
			typeval = typeAndValue.type;
		
		const subjval = typeAndValue.value.valueBlock.value;
		
		const row = issuerTable.insertRow(issuerTable.rows.length);
		const cell0 = row.insertCell(0);
		cell0.innerHTML = typeval;
		const cell1 = row.insertCell(1);
		cell1.innerHTML = subjval;
	}
	//endregion
	
	//region Put information about X.509 certificate subject
	for(const typeAndValue of certificate.subject.typesAndValues)
	{
		let typeval = rdnmap[typeAndValue.type];
		if(typeof typeval === "undefined")
			typeval = typeAndValue.type;
		
		const subjval = typeAndValue.value.valueBlock.value;
		
		const row = subjectTable.insertRow(subjectTable.rows.length);
		const cell0 = row.insertCell(0);
		cell0.innerHTML = typeval;
		const cell1 = row.insertCell(1);
		cell1.innerHTML = subjval;
	}
	//endregion
	
	//region Put information about X.509 certificate serial number
	document.getElementById("cert-serial-number").innerHTML = bufferToHexCodes(certificate.serialNumber.valueBlock.valueHex);
	//endregion
	
	//region Put information about issuance date
	document.getElementById("cert-not-before").innerHTML = certificate.notBefore.value.toString();
	//endregion
	
	//region Put information about expiration date
	document.getElementById("cert-not-after").innerHTML = certificate.notAfter.value.toString();
	//endregion
	
	//region Put information about subject public key size
	let publicKeySize = "< unknown >";
	
	if(certificate.subjectPublicKeyInfo.algorithm.algorithmId.indexOf("1.2.840.113549") !== (-1))
	{
		const asn1PublicKey = asn1js.fromBER(certificate.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHex);
		const rsaPublicKey = new RSAPublicKey({ schema: asn1PublicKey.result });
		
		const modulusView = new Uint8Array(rsaPublicKey.modulus.valueBlock.valueHex);
		let modulusBitLength = 0;
		
		if(modulusView[0] === 0x00)
			modulusBitLength = (rsaPublicKey.modulus.valueBlock.valueHex.byteLength - 1) * 8;
		else
			modulusBitLength = rsaPublicKey.modulus.valueBlock.valueHex.byteLength * 8;
		
		publicKeySize = modulusBitLength.toString();
	}
	
	document.getElementById("cert-keysize").innerHTML = publicKeySize;
	//endregion
	
	//region Put information about signature algorithm
	const algomap = {
		"1.2.840.113549.1.1.2": "MD2 with RSA",
		"1.2.840.113549.1.1.4": "MD5 with RSA",
		"1.2.840.10040.4.3": "SHA1 with DSA",
		"1.2.840.10045.4.1": "SHA1 with ECDSA",
		"1.2.840.10045.4.3.2": "SHA256 with ECDSA",
		"1.2.840.10045.4.3.3": "SHA384 with ECDSA",
		"1.2.840.10045.4.3.4": "SHA512 with ECDSA",
		"1.2.840.113549.1.1.10": "RSA-PSS",
		"1.2.840.113549.1.1.5": "SHA1 with RSA",
		"1.2.840.113549.1.1.14": "SHA224 with RSA",
		"1.2.840.113549.1.1.11": "SHA256 with RSA",
		"1.2.840.113549.1.1.12": "SHA384 with RSA",
		"1.2.840.113549.1.1.13": "SHA512 with RSA"
	};       // array mapping of common algorithm OIDs and corresponding types
	
	let signatureAlgorithm = algomap[certificate.signatureAlgorithm.algorithmId];
	if(typeof signatureAlgorithm === "undefined")
		signatureAlgorithm = certificate.signatureAlgorithm.algorithmId;
	else
		signatureAlgorithm = `${signatureAlgorithm} (${certificate.signatureAlgorithm.algorithmId})`;
	
	document.getElementById("cert-sign-algo").innerHTML = signatureAlgorithm;
	//endregion
	
	//region Put information about certificate extensions
	if("extensions" in certificate)
	{
		for(let i = 0; i < certificate.extensions.length; i++)
		{
			const row = extensionTable.insertRow(extensionTable.rows.length);
			const cell0 = row.insertCell(0);
			cell0.innerHTML = certificate.extensions[i].extnID;
		}
		
		document.getElementById("cert-extn-div").style.display = "block";
	}
	//endregion
}
//*********************************************************************************
function createCertificateInternal()
{
	//region Initial variables 
	let sequence = Promise.resolve();
	
	const certificate = new Certificate();
	
	let publicKey;
	let privateKey;
	
	trustedCertificates = [];
	//endregion
	
	//region Get a "crypto" extension 
	const crypto = getCrypto();
	if(typeof crypto === "undefined")
		return Promise.reject("No WebCrypto extension found");
	//endregion
	
	//region Put a static values 
	certificate.version = 2;
	certificate.serialNumber = new asn1js.Integer({ value: 1 });
	certificate.issuer.typesAndValues.push(new AttributeTypeAndValue({
		type: "2.5.4.6", // Country name
		value: new asn1js.PrintableString({ value: "RU" })
	}));
	certificate.issuer.typesAndValues.push(new AttributeTypeAndValue({
		type: "2.5.4.3", // Common name
		value: new asn1js.BmpString({ value: "Test" })
	}));
	certificate.subject.typesAndValues.push(new AttributeTypeAndValue({
		type: "2.5.4.6", // Country name
		value: new asn1js.PrintableString({ value: "RU" })
	}));
	certificate.subject.typesAndValues.push(new AttributeTypeAndValue({
		type: "2.5.4.3", // Common name
		value: new asn1js.BmpString({ value: "Test" })
	}));
	
	certificate.notBefore.value = new Date(2016, 1, 1);
	certificate.notAfter.value = new Date(2019, 1, 1);
	
	certificate.extensions = []; // Extensions are not a part of certificate by default, it's an optional array
	
	//region "BasicConstraints" extension
	const basicConstr = new BasicConstraints({
		cA: true,
		pathLenConstraint: 3
	});
	
	certificate.extensions.push(new Extension({
		extnID: "2.5.29.19",
		critical: true,
		extnValue: basicConstr.toSchema().toBER(false),
		parsedValue: basicConstr // Parsed value for well-known extensions
	}));
	//endregion 
	
	//region "KeyUsage" extension 
	const bitArray = new ArrayBuffer(1);
	const bitView = new Uint8Array(bitArray);
	
	bitView[0] = bitView[0] | 0x02; // Key usage "cRLSign" flag
	bitView[0] = bitView[0] | 0x04; // Key usage "keyCertSign" flag
	
	const keyUsage = new asn1js.BitString({ valueHex: bitArray });
	
	certificate.extensions.push(new Extension({
		extnID: "2.5.29.15",
		critical: false,
		extnValue: keyUsage.toBER(false),
		parsedValue: keyUsage // Parsed value for well-known extensions
	}));
	//endregion 
	//endregion 
	
	//region Create a new key pair 
	sequence = sequence.then(() =>
	{
		//region Get default algorithm parameters for key generation
		const algorithm = getAlgorithmParameters(signAlg, "generatekey");
		if("hash" in algorithm.algorithm)
			algorithm.algorithm.hash.name = hashAlg;
		//endregion
		
		return crypto.generateKey(algorithm.algorithm, true, algorithm.usages);
	});
	//endregion 
	
	//region Store new key in an interim variables
	sequence = sequence.then(keyPair =>
	{
		publicKey = keyPair.publicKey;
		privateKey = keyPair.privateKey;
	}, error => Promise.reject(`Error during key generation: ${error}`));
	//endregion 
	
	//region Exporting public key into "subjectPublicKeyInfo" value of certificate 
	sequence = sequence.then(() =>
		certificate.subjectPublicKeyInfo.importKey(publicKey)
	);
	//endregion 
	
	//region Signing final certificate 
	sequence = sequence.then(() =>
			certificate.sign(privateKey, hashAlg),
		error => Promise.reject(`Error during exporting public key: ${error}`));
	//endregion 
	
	//region Encode and store certificate 
	sequence = sequence.then(() =>
	{
		trustedCertificates.push(certificate);
		certificateBuffer = certificate.toSchema(true).toBER(false);
	}, error => Promise.reject(`Error during signing: ${error}`));
	//endregion 
	
	//region Exporting private key 
	sequence = sequence.then(() =>
		crypto.exportKey("pkcs8", privateKey)
	);
	//endregion 
	
	//region Store exported key on Web page 
	sequence = sequence.then(result =>
	{
		privateKeyBuffer = result;
	}, error => Promise.reject(`Error during exporting of private key: ${error}`));
	//endregion
	
	return sequence;
}
//*********************************************************************************
function createCertificate()
{
	return createCertificateInternal().then(() =>
	{
		const certificateString = String.fromCharCode.apply(null, new Uint8Array(certificateBuffer));
		
		let resultString = "-----BEGIN CERTIFICATE-----\r\n";
		resultString = `${resultString}${formatPEM(window.btoa(certificateString))}`;
		resultString = `${resultString}\r\n-----END CERTIFICATE-----\r\n`;
		
		parseCertificate();
		
		alert("Certificate created successfully!");
		
		const privateKeyString = String.fromCharCode.apply(null, new Uint8Array(privateKeyBuffer));
		
		resultString = `${resultString}\r\n-----BEGIN PRIVATE KEY-----\r\n`;
		resultString = `${resultString}${formatPEM(window.btoa(privateKeyString))}`;
		resultString = `${resultString}\r\n-----END PRIVATE KEY-----\r\n`;
		
		document.getElementById("new_signed_data").innerHTML = resultString;
		
		alert("Private key exported successfully!");
	}, error =>
	{
		if(error instanceof Object)
			alert(error.message);
		else
			alert(error);
	});
}
//*********************************************************************************
function verifyCertificateInternal()
{
	//region Initial variables
	let sequence = Promise.resolve();
	//endregion
	
	//region Major activities
	sequence = sequence.then(() =>
	{
		// #region Initial check
		if(certificateBuffer.byteLength === 0)
			return Promise.resolve({ result: false });
		// #endregion
		
		// #region Decode existing CERT
		const asn1 = asn1js.fromBER(certificateBuffer);
		const certificate = new Certificate({ schema: asn1.result });
		// #endregion
		
		// #region Create certificate's array (end-user certificate + intermediate certificates)
		const certificates = [];
		certificates.push(certificate);
		certificates.push(...intermadiateCertificates);
		// #endregion
		
		// #region Make a copy of trusted certificates array
		const trustedCerts = [];
		trustedCerts.push(...trustedCertificates);
		// #endregion
		
		// #region Create new X.509 certificate chain object
		const certChainVerificationEngine = new CertificateChainValidationEngine({
			trustedCerts,
			certs: certificates,
			crls
		});
		// #endregion
		
		// #region Verify CERT
		return certChainVerificationEngine.verify();
		// #endregion
	});
	//endregion
	
	//region Error handling stub
	sequence = sequence.then(result => result, error => Promise.resolve(false));
	//endregion
	
	return sequence;
}
//*********************************************************************************
function verifyCertificate()
{
	return verifyCertificateInternal().then(result =>
	{
		alert(`Verification result: ${result.result}`);
	}, error =>
	{
		alert(`Error during verification: ${error.resultMessage}`);
	});
}
//*********************************************************************************
function parseCAbundle(buffer)
{
	// #region Initial variables
	const base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
	
	const startChars = "-----BEGIN CERTIFICATE-----";
	const endChars = "-----END CERTIFICATE-----";
	const endLineChars = "\r\n";
	
	const view = new Uint8Array(buffer);
	
	let waitForStart = false;
	let middleStage = true;
	let waitForEnd = false;
	let waitForEndLine = false;
	let started = false;
	
	let certBodyEncoded = "";
	// #endregion
	
	for(let i = 0; i < view.length; i++)
	{
		if(started === true)
		{
			if(base64Chars.indexOf(String.fromCharCode(view[i])) !== (-1))
				certBodyEncoded = certBodyEncoded + String.fromCharCode(view[i]);
			else
			{
				if(String.fromCharCode(view[i]) === "-")
				{
					// #region Decoded trustedCertificates
					const asn1 = asn1js.fromBER(stringToArrayBuffer(window.atob(certBodyEncoded)));
					try
					{
						trustedCertificates.push(new Certificate({ schema: asn1.result }));
					}
					catch(ex)
					{
						alert("Wrong certificate format");
						return;
					}
					// #endregion
					
					// #region Set all "flag variables"
					certBodyEncoded = "";
					
					started = false;
					waitForEnd = true;
					// #endregion
				}
			}
		}
		else
		{
			if(waitForEndLine === true)
			{
				if(endLineChars.indexOf(String.fromCharCode(view[i])) === (-1))
				{
					waitForEndLine = false;
					
					if(waitForEnd === true)
					{
						waitForEnd = false;
						middleStage = true;
					}
					else
					{
						if(waitForStart === true)
						{
							waitForStart = false;
							started = true;
							
							certBodyEncoded = certBodyEncoded + String.fromCharCode(view[i]);
						}
						else
							middleStage = true;
					}
				}
			}
			else
			{
				if(middleStage === true)
				{
					if(String.fromCharCode(view[i]) === "-")
					{
						if((i === 0) ||
							((String.fromCharCode(view[i - 1]) === "\r") ||
							(String.fromCharCode(view[i - 1]) === "\n")))
						{
							middleStage = false;
							waitForStart = true;
						}
					}
				}
				else
				{
					if(waitForStart === true)
					{
						if(startChars.indexOf(String.fromCharCode(view[i])) === (-1))
							waitForEndLine = true;
					}
					else
					{
						if(waitForEnd === true)
						{
							if(endChars.indexOf(String.fromCharCode(view[i])) === (-1))
								waitForEndLine = true;
						}
					}
				}
			}
		}
	}
}
//*********************************************************************************
function handleFileBrowse(evt)
{
	const tempReader = new FileReader();
	
	const currentFiles = evt.target.files;
	
	tempReader.onload =
		function(event)
		{
			certificateBuffer = event.target.result;
			parseCertificate();
		};
	
	tempReader.readAsArrayBuffer(currentFiles[0]);
}
//*********************************************************************************
function handleTrustedCertsFile(evt)
{
	const tempReader = new FileReader();
	
	const currentFiles = evt.target.files;
	let currentIndex = 0;
	
	tempReader.onload =
		function(event)
		{
			try
			{
				const asn1 = asn1js.fromBER(event.target.result);
				const certificate = new Certificate({ schema: asn1.result });
				
				trustedCertificates.push(certificate);
			}
			catch(ex)
			{
			}
		};
	
	tempReader.onloadend =
		function(event)
		{
			if(event.target.readyState === FileReader.DONE)
			{
				currentIndex++;
				
				if(currentIndex < currentFiles.length)
					tempReader.readAsArrayBuffer(currentFiles[currentIndex]);
			}
		};
	
	tempReader.readAsArrayBuffer(currentFiles[0]);
}
//*********************************************************************************
function handleInterCertsFile(evt)
{
	const tempReader = new FileReader();
	
	const currentFiles = evt.target.files;
	let currentIndex = 0;
	
	tempReader.onload =
		function(event)
		{
			try
			{
				const asn1 = asn1js.fromBER(event.target.result);
				const certificate = new Certificate({ schema: asn1.result });
				
				intermadiateCertificates.push(certificate);
			}
			catch(ex)
			{
			}
		};
	
	tempReader.onloadend =
		function(event)
		{
			if(event.target.readyState === FileReader.DONE)
			{
				currentIndex++;
				
				if(currentIndex < currentFiles.length)
					tempReader.readAsArrayBuffer(currentFiles[currentIndex]);
			}
		};
	
	tempReader.readAsArrayBuffer(currentFiles[0]);
}
//*********************************************************************************
function handleCRLsFile(evt)
{
	const tempReader = new FileReader();
	
	const currentFiles = evt.target.files;
	let currentIndex = 0;
	
	tempReader.onload =
		function(event)
		{
			try
			{
				const asn1 = asn1js.fromBER(event.target.result);
				const crl = new CertificateRevocationList({ schema: asn1.result });
				
				crls.push(crl);
			}
			catch(ex)
			{
			}
		};
	
	tempReader.onloadend =
		function(event)
		{
			if(event.target.readyState === FileReader.DONE)
			{
				currentIndex++;
				
				if(currentIndex < currentFiles.length)
					tempReader.readAsArrayBuffer(currentFiles[currentIndex]);
			}
		};
	
	tempReader.readAsArrayBuffer(currentFiles[0]);
}
//*********************************************************************************
function handleCABundle(evt)
{
	const tempReader = new FileReader();
	
	const currentFiles = evt.target.files;
	
	tempReader.onload =
		function(event)
		{
			parseCAbundle(event.target.result);
		};
	
	tempReader.readAsArrayBuffer(currentFiles[0]);
}
//*********************************************************************************
function handleHashAlgOnChange()
{
	const hashOption = document.getElementById("hash_alg").value;
	switch(hashOption)
	{
		case "alg_SHA1":
			hashAlg = "sha-1";
			break;
		case "alg_SHA256":
			hashAlg = "sha-256";
			break;
		case "alg_SHA384":
			hashAlg = "sha-384";
			break;
		case "alg_SHA512":
			hashAlg = "sha-512";
			break;
		default:
	}
}
//*********************************************************************************
function handleSignAlgOnChange()
{
	const signOption = document.getElementById("sign_alg").value;
	switch(signOption)
	{
		case "alg_RSA15":
			signAlg = "RSASSA-PKCS1-V1_5";
			break;
		case "alg_RSA2":
			signAlg = "RSA-PSS";
			break;
		case "alg_ECDSA":
			signAlg = "ECDSA";
			break;
		default:
	}
}
//*********************************************************************************
context("Hack for Rollup.js", () =>
{
	return;
	createPKCS10();
	parsePKCS10();
	verifyPKCS10();
	parseCertificate();
	createCertificate();
	verifyCertificate();
	parseCAbundle();
	handleFileBrowse();
	handleTrustedCertsFile();
	handleInterCertsFile();
	handleCRLsFile();
	handleCABundle();
	handleHashAlgOnChange();
	handleSignAlgOnChange();
	setEngine();
});
//*********************************************************************************

