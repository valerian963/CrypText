const io = require('socket.io-client');
const Blowfish = require('blowfish');
const { createDiffieHellman } = require('crypto');
const bcrypt = require('bcrypt');

const socket = io('http://localhost:3000'); 
let sharedSecret = null;
let usersNotFriends = []
let privateKeyFriends = {}


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
    // login do usuário
    loginUser();
    }
  });
});

socket.on('disconnect', () => {
  console.log('Desconectado do servidor.');
});


// Função para logar o usuário
async function loginUser() {
  const loginData = {
    email: 'teste_3@mail.com',
    password:'senha'
  };
  const encryptedData = encryptDataBlowfish(loginData, sharedSecret);
  socket.emit('login', encryptedData, (response) => {
    console.log('Resposta de login:', response.message);
    if (response.success) {
      console.log('Usuário logado com sucesso. ID:');
      // adicionar usuário como online e logado no servidor
      socket.emit('online-loged', 'testinho', (callback) => {
        console.log('O que aconteceu enquanto estava offline:', callback);
      });
      // Listar usuários disponíveis
      listUsers();
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
function acceptFriendRequest() {
  const friendData = {
    friend1: 'usuarioTeste',
    friend2: 'testinho'
  };
  const encryptedData = encryptDataBlowfish(friendData, sharedSecret);
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

socket.on('receive-friend-request', (encryptedData) => {
  try {
    // Descriptografa os dados recebidos usando a chave compartilhada local
    const sharedKey = getLocalSharedKey(); // Função que retorna a chave compartilhada do cliente
    const decryptedData = decryptDataBlowfish(encryptedData, sharedKey);

    // Extraia os dados necessários para criar a chave compartilhada
    const { friend1, p, g, publicKey_friend1 } = decryptedData;

    // Crie a chave Diffie-Hellman usando os parâmetros recebidos
    const clientDH = crypto.createDiffieHellman(p, g, 'hex');
    const clientPublicKey = clientDH.generateKeys('hex');

    // Gere a chave compartilhada usando a chave pública do amigo (friend1)
    const sharedSecretKey = clientDH.computeSecret(publicKey_friend1, 'hex', 'hex');

    // Notificar o usuário sobre a solicitação de amizade recebida
    notifyUser(`${friend1} enviou uma solicitação de amizade!`);

    // Aqui você pode decidir armazenar ou usar a chave compartilhada gerada
    saveSharedSecretKey(friend1, sharedSecretKey);

  } catch (error) {
    console.error('Erro ao processar a solicitação de amizade:', error.message);
  }
});