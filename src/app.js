var express = require('express');
var socketio = require('socket.io');
var RSA = require('node-rsa');
global.config = require('./config.json');
var db = require('./middleware/db.js');
var app = express();
var PORT = 4321;

if('SSL' in global.config){
  var https = require('https');
  var fs = require('fs');
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
    var key = new RSA();
    key.importKey(results[0].PublicKey, 'public');
    var verified = key.verify(username, signature);
    return callback(null, verified, results[0].PublicKey);
  });
}

io.on('connection', function(socket){
  console.log('Client connected', socket.id);
  socket.on('login', function(data){
    verifySignature(data.Username, data.Signature, function(err, verified, publickey){
      if(err){
        return socket.emit('loginResponse', {Success:false, Error:err});
      }
      socketToUser[socket.id] = data.Username;
      userToSocket[data.Username] = socket.id;
      socket.broadcast.emit('friendsupdate');
      return socket.emit('loginResponse', {Success:verified});
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
      return socket.emit('registerResponse', {Success:true});
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
  socket.on('sending', function(data){
    console.log(data);
    var recipient = userToSocket[data.To];
    io.to(recipient).emit('sending', {From: socketToUser[socket.id]});
  });
  socket.on('disconnect', function(){
    var username = socketToUser[socket.id];
    delete socketToUser[socket.id];
    delete userToSocket[username];
    socket.broadcast.emit('friendsupdate');
  });
});
