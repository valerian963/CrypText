const io = require('socket.io-client');
const Blowfish = require('blowfish');
const { createDiffieHellman } = require('crypto');

const socket = io('http://192.168.15.6:3000'); 
let sharedSecret = null;
let usersNotFriends = []
let privateKeyFriends = {}
let solicitacoes = {}
let mensagensOff = {}
let solicitacoesAceitas = {}

const minhaSenha = 'senha_segura'

function cleanJson(jsonString) {
  const jsonLimpo = jsonString.replace(/[^{}[\]_@#!?":,a-zA-Z0-9\s.-]/g, "");

  try {
    const resultado = JSON.parse(jsonLimpo);
    //console.log("JSON válido após limpeza.");
    return resultado;
  } catch (error) {
    console.log("A limpeza falhou ao produzir JSON válido:", error.message);
    return null; // Retorna null se ainda não estiver em um formato válido
  }
}

// criptografia local Blowfish
function encryptDataBlowfish(data, key) {
  const jsonString = JSON.stringify(data);
  const bf = new Blowfish(key);
  const encryptedText = bf.encrypt(jsonString);
  return encryptedText.toString('hex');
}

const decryptDataBlowfish = (encryptedData, key) => {
  const bf = new Blowfish(key);
  const decryptedString = bf.decrypt(encryptedData);
  console.log('Texto descriptografado:', decryptedString);    
  return (cleanJson(decryptedString));
};


// diffie-Hellman
function startDiffieHellman() {
  const dh = createDiffieHellman(512);
  const p = dh.getPrime('hex');
  const g = dh.getGenerator('hex');
  const publicKey = dh.generateKeys('hex');
  return { dh, p, g, publicKey };
}

function calculateSharedKey(dh, otherPublicKey) {
  return dh.computeSecret(otherPublicKey, 'hex', 'hex');
}

// início da conexão webSocket
socket.on('connect', (callback) => {
  console.log('Conectado ao servidor.');

  // inicia diffie-Hellman e envia dados ao servidor
  const { dh, p, g, publicKey } = startDiffieHellman();
  socket.emit('diffie-hellman', p, g, publicKey, (response) => {
    const serverPublicKey = response.PublicKeyServer;
    sharedSecret = calculateSharedKey(dh, serverPublicKey);
    const diffieData = {
      p_value:p,
      g_value: g,
      publicKeyUser: publicKey, 
      userPrivateKey:dh.getPrivateKey('hex'),
      sharedKey: sharedSecret
    };
    console.log("Dados Diffie-Hellman Usuário: ", diffieData);
    
    if(response.success){

      // registra um usuário
    registerUser();

    // login do usuário
    loginUser();
    }
  });
});

socket.on('disconnect', () => {
  console.log('Desconectado do servidor.');
});

// registrar um usuário
async function registerUser() {
  const userData = {
    name: 'Teste',
    email: 'teste@mail.com',
    password: minhaSenha,
    user_name: 'testinho',
    image: null
  };
  const encryptedData = encryptDataBlowfish(userData, sharedSecret);
  socket.emit('register', encryptedData, (success) => {
    if (success) {
      console.log('Registro de usuário concluído.');
    } else {
      console.log('Falha no registro do usuário.');
    }
  });
}

// Função para logar o usuário
async function loginUser() {
  const loginData = {
    email: 'teste@mail.com',
    password:minhaSenha
  };
  const encryptedData = encryptDataBlowfish(loginData, sharedSecret);
  socket.emit('login', encryptedData, (response) => {
    console.log('Resposta de login:', response.message);
    if (response.success) {
      console.log('Usuário logado com sucesso.');
      // adicionar usuário como online e logado no servidor
      socket.emit('online-loged', 'testinho', (callback) => {
        if (callback.success){
          console.log('O que aconteceu enquanto estava offline:', callback);
          const decryptSolicitacoes = decryptDataBlowfish(callback.friendRequests, sharedSecret);
          const descryptMessages = decryptDataBlowfish(callback.offlineMessages, sharedSecret);
          const decryptAccept = decryptDataBlowfish(callback.acceptedRequests, sharedSecret);
          solicitacoes[decryptSolicitacoes.friend1] = {decryptSolicitacoes};
          mensagensOff[descryptMessages.friend2] = {descryptMessages};
          solicitacoesAceitas[decryptAccept.friend2] = {decryptAccept}
          socket.emit('online-users', (result) => {
            console.log("Usuários online: ", result);
            });
        };
      });
      // Listar usuários disponíveis
      listUsers();
    }
  });
}

// Função para listar usuários
function listUsers() {
  socket.emit('list-users', 'testinho', (users) => {
    console.log('Lista de usuários (nao amigos):', users);

    usersNotFriends = users

    listFriends()
  });
}

// Função para listar amigos
function listFriends() {
  socket.emit('list-friends', 'testinho', (response) => {
    try{
      if(response.success){
        const decryptedMessage = decryptDataBlowfish(response.friends, sharedSecret);
        
  
      if (decryptedMessage.length > 0) {
        console.log('Lista de amigos:', decryptedMessage);
        console.log("Mandando mensagem para amigo------------------------------------")
        // enviar mensagem para o primeiro amigo na lista
        sendMessage(decryptedMessage[0].friend2);

        console.log("Solicitando amigo------------------------------------")
        //solicitar amigo
        solicitFriend(usersNotFriends[0].user_name)

        
      }
      }
      else {
        console.log('Lista de amigos vazia\nSolicitando amigo------------------------------------');

        //solicitar amigo
        solicitFriend(usersNotFriends[0].user_name)
        console.log("Mandando mensagem para amigo------------------------------------")
        sendMessage(usersNotFriends[0].user_name);
        
      }  
    }
    catch(error){
      console.log('Erro: ', error);
    }
    
  });
}


function solicitFriend(friend_user) {

  const { dh, p, g, publicKey } = startDiffieHellman();
  privateKeyFriends[friend_user] = dh.getPrivateKey('hex');;
  const friendData = {
    user_name1: 'testinho',
    user_name2: friend_user,
    p_value: p,
    g_value: g,
    publicKey_friend1: publicKey
  };
  console.log("Dados de solicitação de amizade: ", friendData)
  const encryptedData = encryptDataBlowfish(friendData, sharedSecret);
  socket.emit('friend-request', encryptedData, (response) => {
      if (response.success){
        console.log("Solicitação registrada");
      }
      else{
        console.log("Falha da solicitação");
      }
  
    
  });
}

// enviar mensagem
function sendMessage(recipientUserName) {
  const messageData = {
    sender_user_name: 'testinho',
    recipient_user_name: recipientUserName,
    timestamp: new Date().toISOString(),
    message: 'oi, mensagem de teste!'
  };

  console.log("Dados de envio de mensagem: ", messageData)
  const encryptedData = encryptDataBlowfish(messageData, sharedSecret);
  socket.emit('send-message', encryptedData);
}

// recebe mensagem
socket.on('receive-message', (encryptedData) => {
  const decryptedMessage = decryptDataBlowfish(encryptedData, sharedSecret);
  console.log('Mensagem recebida:', decryptedMessage);
});

// aceitar solicitação de amizade 
function acceptFriendRequest(friend_user) {
  // const friendData = {
  //   friend1: 'usuarioTeste',
  //   friend2: 'testinho'
  // };
  const encryptedData = encryptDataBlowfish({user_name1: user_name, user_name2: solicitacoes[friend_user].friend1, publicKey_friend2 }, sharedSecret);
  socket.emit('accept-friend', encryptedData);
}

function rejectFriendRequest(){
  const friendData = {
    friend1: 'vallyria',
    friend2: 'testinho'
  };
  const encryptedData = encryptDataBlowfish(friendData, sharedSecret);
  socket.emit('accept-friend', encryptedData);
}