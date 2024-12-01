// CRIPTOGRAFIA ------------------------------------------------------------------------------------------------------------------------
  
  // Diffie Hellman - Função para gerar p, g e chave publica
function startDiffieHellman() {
    const dh = createDiffieHellman(512); // 512 bits para segurança
    const p = dh.getPrime('hex');
    const g = dh.getGenerator('hex');
    const publicKey = dh.generateKeys('hex');
  
    return { dh, p, g, publicKey };
  }
  
function calculateSharedKey(dh, otherPublicKey) {
    const sharedKey = dh.computeSecret(otherPublicKey, 'hex', 'hex');
    return sharedKey; // Usada para criptografia Blowfish
  }
  
  
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
    diffieHellmanSharedKeysUsers[socketid] = sharedKey;
    // envia a chave pública do servidor de volta ao cliente
    return publicKey;
  };

module.exports = {startDH};