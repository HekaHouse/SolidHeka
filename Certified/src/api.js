
var DOMAIN = 'https://heka.house';
var ACCOUNT_ENDPOINT = ',system/newAccount';
var CERT_ENDPOINT = ',system/newCert';


var accURL = {};


function init() {
	var parser = document.createElement('a');
	parser.href = DOMAIN;
	accURL.host = parser.host + '/'; // => "example.com"
	accURL.path = parser.pathname; // => "/pathname/"
	accURL.schema = parser.protocol + '//';	
}

init();



var makeURI = function(username) {
  if (username.length > 0) {
    return accURL.schema + username + '.' + accURL.host;
  }
  return null;
}

var makeHost = function(username) {
  if (username.length > 0) {
    return username + '.' + accURL.host;
  }
  return null;
}



var requestPersona = function(persona,cb) {
	
	
	if (persona.indexOf('-') === 0) {
		persona = persona.slice(1);
	}
	if (persona.lastIndexOf('-') === persona.length - 1) {
		persona = persona.slice(0, -1)
	}

	if (persona.length > 0) {
		// var mrp = require('minimal-request-promise');
		// options = {
		//     method: 'HEAD',				    
		//     hostname: makeURI(persona),
		//     path: '/',
		//     port: 443,
		//     headers: {},
		//     body: ''
		// };
		// return mrp(options).then(
		//   function (response) {
		//     return response.statusCode;
		//   },
		//   function (response) {
		//   	if (response.statusCode === undefined) {
		//   		return '999';
		//   	}
		//     return response.statusCode;
		//   }
		// );
		var url = makeURI(persona,function(status){
			console.log('status',status);
		});
		var http = new XMLHttpRequest();
		http.open('HEAD', makeURI(persona));
		http.onreadystatechange = function() {
		  console.log(this.status)
		    if (this.readyState == this.DONE) {
		      if (this.status === 0) {
		      	console.log('not connected');
		        cb('999');		        
		      } else if (this.status === 404) {
		        cb('404');
		      } else {
		        cb(this.status);
		      }
		    }
		};
		http.send();
	}
	
};


var createAccount = function(account,email,cb) {
	if (account.length > 0) {
		generateRSAKeyPair()
		.then(function(keyPair){			
			storeKeys(keyPair);		
			return generateCSR(keyPair,db,definePersonaCSR(account));
		})
		.then(function(csr){			
			storeKeyValue(db,'csr',csr);				
			certified.verifyCSR(csr)
			.then(function(verified){
				console.log(verified);
				if (verified) {
					certified.parseCSR(csr)
					.then(function(csrStruct){
						return JSON.stringify(csrStruct);
					})
					.then(function(csrStr){
						var url = makeURI(account) + ACCOUNT_ENDPOINT;
						var data = "username="+account+"&email="+email+"&csr="+csrStr;
						var http = new XMLHttpRequest();
						http.open('POST', url);
						http.withCredentials = true;
						http.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
						http.onreadystatechange = function() {
						    if (this.readyState == this.DONE) {
						      if (this.status === 200) {
								console.log('Account created at '+url);
						      } else {
						        console.log('Error creating account at '+url);
						      }
						    }
						};
						http.send(data);
						//document.querySelector("#spkacWebID").value = csrStr;
					});
				}
			});			
		});



	}
};

window.requestPersona = requestPersona;

window.createAccount = createAccount;