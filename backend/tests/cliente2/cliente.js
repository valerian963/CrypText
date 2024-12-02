const io = require('socket.io-client');
const blowfish = require('/home/dialog/Redes/CrypText/backend/cryptography/blowfish.js');

const socket = io('http://localhost:3000'); 
let sharedSecret = null;
let usersNotFriends = []
let privateKeyFriends = {}

// início da conexão webSocket
socket.on('connect', (callback) => {
  console.log('Conectado ao servidor.');

  const myname = blowfish.encryptDataBlowfish('testinho','senha')
  socket.emit('list-friends',myname,(callback) =>{
    console.log(callback)
    console.log(blowfish.decryptDataBlowfish(callback.friends, 'senha'));
  }
)
});

socket.on('disconnect', () => {
  console.log('Desconectado do servidor.');
});
