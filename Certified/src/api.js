
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

exports.requestPersona = function(persona) {
	
	
	if (persona.indexOf('-') === 0) {
		persona = persona.slice(1);
	}
	if (persona.lastIndexOf('-') === persona.length - 1) {
		persona = persona.slice(0, -1)
	}

	if (persona.length > 0) {
		var mrp = require('minimal-request-promise');
		options = {
		    method: 'HEAD',				    
		    hostname: makeURI(persona),
		    path: '/',
		    port: 80,
		    headers: {},
		    body: ''
		};
		return mrp(options).then(
		  function (response) {
		    return response.statusCode;
		  },
		  function (response) {
		  	if (response.statusCode === undefined) {
		  		return '999';
		  	}
		    return response.statusCode;
		  }
		);
		// var url = makeURI(persona);
		// var http = new XMLHttpRequest();
		// http.open('HEAD', 'file:///C:/Users/aron2/Documents/GitHub/Certified/balogna.html');
		// http.onreadystatechange = function() {
		//   console.log(this.status)
		//     if (this.readyState == this.DONE) {
		//       if (this.status === 0) {
		//       	console.log('not connected');
		//         return '999';		        
		//       } else if (this.status === 404) {
		//         return '404';
		//       } else {
		//         return this.status;
		//       }
		//     }
		// };
		// http.send();
	}
	
};


exports.createAccount = function(account,email) {
	if (account.length > 0) {
		var url = makeURI(account) + ACCOUNT_ENDPOINT;
		var data = "username="+account+"&email="+email;
		var http = new XMLHttpRequest();
		http.open('POST', url);
		http.withCredentials = true;
		http.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
		http.onreadystatechange = function() {
		    if (this.readyState == this.DONE) {
		      if (this.status === 200) {

		      } else {
		        console.log('Error creating account at '+url);
		      }
		    }
		};
		http.send(data);
	}
};