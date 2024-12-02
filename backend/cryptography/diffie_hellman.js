// CRIPTOGRAFIA ------------------------------------------------------------------------------------------------------------------------
const BigInteger = require('big-integer'); 

// guarda as chaves Diffie-Hellman de cada usuário temporariamente
let diffieHellmanSharedKeysUsers = {};

function startDH(socketid, pa, ga, clientPublicKey) {
    const p = BigInteger(pa)
    const g = BigInteger(ga)
    // Chave privada escolhida aleatoriamente pelo servidor
    const privateKey = BigInteger.randBetween(BigInteger(1), p.minus(1));
  
    const publicKey = g.modPow(privateKey, p);
  
    const sharedKey = BigInteger(clientPublicKey).modPow(privateKey, p);
  
    const diffieData = {
      publicServerKey:publicKey, 
      privateServerKey:privateKey, 
      sharedKeyValue:sharedKey
    };
    console.log('Chaves geradas no servidor: ', diffieData);
  
    // guarda a chave compartilhada para tal usuário tenporariamente
    diffieHellmanSharedKeysUsers[socketid] = String(sharedKey);
    // envia a chave pública do servidor de volta ao cliente
    return publicKey;
  };

module.exports = {startDH, diffieHellmanSharedKeysUsers};