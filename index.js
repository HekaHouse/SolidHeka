var fs = require('fs');
var http = require('http');
var https = require('https');
var solid = require('solid-server');
var wildcardSubdomains = require('wildcard-subdomains');
var cors = require('cors');
var bodyParser = require('body-parser');
var multer  = require('multer');
var upload = multer({ dest: 'uploads/' });

var settings = {
  cache: 0, // Set cache time (in seconds), 0 for no cache
  live: true, // Enable live support through WebSockets
  root: './solid', // Root location on the filesystem to serve resources
  secret: 'node-ldp', // Express Session secret key
  sslCert: '../ssl/heka.house.crt', // Path to the ssl cert
  sslKey: '../ssl/heka.house.key', // Path to the ssl key
  mount: '/solid', // Where to mount Linked Data Platform
  webid: true, // Enable WebID+TLS authentication
  suffixAcl: '.acl', // Suffix for acl files
  proxy: false, // Where to mount the proxy
  errorHandler: false, // function(err, req, res, next) to have a custom error handler
  errorPages: false // specify a path where the error pages are
};



var admin = require("firebase-admin");

var serviceAccount = require("../api/serviceAccountKey.json");

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: "https://heka-house-df9b8.firebaseio.com"
});

var database = admin.database();
var storage = admin.storage();

var privateKey  = fs.readFileSync('../ssl/heka.house.key', 'utf8');
var certificate = fs.readFileSync('../ssl/heka.house.crt', 'utf8');
var ca = fs.readFileSync('../ssl/ca.crt', 'utf8');

var credentials = {key: privateKey, cert: certificate, ca: ca};
var express = require('express');
var app = express();

app.use(bodyParser.urlencoded({
  extended: true
}));
app.use(bodyParser.json());


// your express configuration here

var httpServer = http.createServer(app);
var httpsServer = https.createServer(credentials, app);

var corsOptions = {
	origin: /(.*\.)?heka\.house$/,
	regExp: true,
	credentials: true,
	optionsSuccessStatus: 200
}

app.use(cors(corsOptions));

app.use(wildcardSubdomains({
  namespace: 's',
  whitelist: ['www'],
}));


app.use('/signup.html', express.static('solid-signup'))

app.use('/solid', solid(settings));

app.get('/', function (req, res) {
  res.send('Hello World!');
});


///s/*/,system/newAccount
//{"username":"aron","email":"aron@heka.house"}

///s/*/,system/newCert
//{"webid":"","name":"Aron Price"}

app.get('/s/*', function (req, res) {
  console.log('checking',req.hostname.replace('.heka.house',''));
  database.ref('/users/'+req.hostname.replace('.heka.house','')).once('value').then(function(snapshot) {
    if (snapshot.val()) {
    	res.status(200).send(snapshot.val());
    } else {
        res.status(404).send('not found');
    }
  });
});

app.post('/s/*/,system/newAccount', function (req, res) {
  var username = req.body.username;
  var email = req.body.email;
  var ref = database.ref('/users').child(username);
  ref.set({'created':Math.floor(Date.now())});
  if (email) {
    ref.child('email').set(email);
  }
  returnRef(ref,res);
});

app.post('/s/*/profile', upload.single('avatar'), function (req, res) {
  var username = req.hostname.replace('.heka.house','');
  var fullname = req.body.name;
  var avatar = req.file;
  var userRef = database.ref('/users').child(username);
  var avatarRef = storage.ref().child('user-content/images/'+username+'/profile');
  if (fullname) {
    userRef.child('fullname').set(fullname);
  }
  if (avatar) {
    avatarRef.put(avatar.buffer).then(function(snapshot) {
      console.log('Uploaded a profile!');
      avatarRef.getDownloadURL().then(function(url) {
        userRef.child('avatar').set(url); 
        returnRef(userRef,res);  
      });
    });  
  } else {
    returnRef(userRef,res);
  }
});

function returnRef(ref,res) {
  ref.once('value').then(function(snapshot) {
    if (snapshot.val()) {
        res.status(200).send(snapshot.val());
    } else {
        res.status(503).send('something went wrong');
    }
  });  
}

app.patch('/s/*/profile/card', function (req, res) {
        console.log(JSON.stringify(req.params));
        console.log(JSON.stringify(req.body));
        console.log(JSON.stringify(req.query));
        res.sendStatus(200);
});

app.post('/s/*/,system/newCert', function (req, res) {
        console.log(JSON.stringify(req.params));
        console.log(JSON.stringify(req.body));
        console.log(JSON.stringify(req.query));
        res.sendStatus(200);
});


httpServer.listen(3000);
httpsServer.listen(3443);





