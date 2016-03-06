var express = require('express');
var socketio = require('socket.io');
var crypto = require('crypto');
var fs = require('fs');
global.config = require('./config.json');
var db = require('./middleware/db');
var app = express();
var PORT = 4321;
var keys;
var handshakeData;

if('SSL' in global.config){
  var https = require('https');
  var config = {
    key: fs.readFileSync(global.config.SSL.keyfile),
    cert: fs.readFileSync(global.config.SSL.certfile),
    ca: fs.readFileSync(global.config.SSL.chainfile)
  };
  var server = https.createServer(config, app);
  console.log('Using HTTPS!');
}
else{
  var http = require('http');
  var server= http.Server(app);
}


try{
  var keytext = fs.readFileSync(global.config.Key.Path);
  var decipher = crypto.createDecipher('aes256', global.config.Key.Password);
  var dec = decipher.update(keytext, 'hex');
  dec += decipher.final('hex');
  keys = JSON.parse(dec);
  var sign = crypto.createSign('RSA-SHA512');
  sign.update(keys.public);
  var signatue = sign.sign(keys.private, 'hex');
  handshakeData = {PublicKey: keys.public, Signature:signature};
} catch(e){
  if (e.code === 'ENOENT') {
    console.log('no keys found!\n Generating new keypair');
    var keypair = require('keypair');
    keys = keypair({bits:4096});
    var keytext = JSON.stringify(keys);
    var cipher = crypto.createCipher('aes256', global.config.Key.Password);
    var enc = cipher.update(keytext, 'utf8', 'hex');
    enc += cipher.final('hex');
    fs.writeFileSync(global.config.Key.Path, enc);
    var sign = crypto.createSign('RSA-SHA512');
    sign.update(keys.public);
    var signatue = sign.sign(keys.private, 'hex');
    handshakeData = {PublicKey: keys.public, Signature:signature};
  } else {
    throw e;
  }
}

var io = socketio(server);
server.listen(PORT);
console.log('Server started on port', PORT);
var userToSocket = {};
var socketToUser={};

function verifySignature(username, signature, callback){
  var user = db.query('Select PublicKey from users where Username=?', [username],function(err,results){
    if(err){
      return callback(err);
    }
    if(results.length<1){
      return callback('No Such Username');
    }
    var verify = crypto.createVerify('RSA-SHA512');
    verify.update(username);
    var verified = verify.verify(results[0].PublicKey, signature, 'hex');
    return callback(null, verified, results[0].PublicKey);
  });
}

app.get('/key/:username', function(req, res){
  var username = req.params.username;
  db.query('Select PublicKey from users where Username = ? LIMIT 1;', [username], function(err, results){
    if(err){
      return res.send({Success: false, Error: err});
    }
    if(results.length<1){
      return res.send({Success: false, Error: 'No user by that username'});
    }
    return res.send({Success: true, Username: username, Key: results[0].PublicKey});
  });
});

io.on('connection', function(socket){
  console.log('Client connected', socket.id);
  socket.emit('connected', handshakedata);
  socket.on('login', function(data){
    verifySignature(data.Username, data.Signature, function(err, verified, publickey){
      if(err){
        return socket.emit('loginResponse', {Success:false, Error:err});
      }
      if(verified){
        socketToUser[socket.id] = data.Username;
        userToSocket[data.Username] = socket.id;
        socket.broadcast.emit('friendsupdate');
      }
      return socket.emit('loginResponse', {Success:verified, Username: data.Username});
    });
  });
  socket.on('register', function(data){
    db.query('Insert into users (Username, PublicKey) VALUES(?, ?);', [data.Username, data.PublicKey], function(err, result){
      if(err){
        return socket.emit('registerResponse', {Success:false, Error:err});
      }
      socketToUser[socket.id] = data.Username;
      userToSocket[data.Username] = socket.id;
      socket.broadcast.emit('friendsupdate');
      return socket.emit('registerResponse', {Success:true, Username:data.Username});
    });
  });
  socket.on('getFriends', function(username){
    db.query('Select Username from users where Username != ?;', [username], function(err, results){
      if(err){
        return socket.emit('getFriendsResponse', {Success: false, Error: err});
      }
      results.forEach(function(r){
        if(userToSocket[r.Username]){
          r.Active = true;
        }
        else{
          r.Active=false;
        }
      });
      return socket.emit('getFriendsResponse', {Success: true, Friends: results});
    });
  });
  socket.on('getKey', function(username){
    console.log('getting key for', username);
    db.query('Select PublicKey from users where Username = ? LIMIT 1;', [username], function(err, results){
      if(err){
        return socket.emit('getKeyResponse', {Success: false, Error: err});
      }
      if(results.length<1){
        return socket.emit('getKeyResponse', {Success: false, Error: 'No user by that username'});
      }
      return socket.emit('getKeyResponse', {Success: true, Username: username, Key: results[0].PublicKey});
    });
  });
  socket.on('message', function(data){
    var recipient = userToSocket[data.To];
    data.From = socketToUser[socket.id];
    io.to(recipient).emit('message', data);
  });
  socket.on('filetransfer', function(data){
    var recipient = userToSocket[data.To];
    data.From = socketToUser[socket.id];
    io.to(recipient).emit('filetransfer', data);
  });
  socket.on('disconnect', function(){
    var username = socketToUser[socket.id];
    delete socketToUser[socket.id];
    delete userToSocket[username];
    socket.broadcast.emit('friendsupdate');
  });
});
