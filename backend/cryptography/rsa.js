const forge = require("node-forge");
const pki = forge.pki;

// Geração de Par de Chaves 
const generateKeyPair = () => {
    const keys = pki.rsa.generateKeyPair(2048);
    return {
        publicKey: keys.publicKey,    // forge.pki.PublicKey object
        privateKey: keys.privateKey,  // forge.pki.PrivateKey object
        publicKeyPem: pki.publicKeyToPem(keys.publicKey),
        privateKeyPem: pki.privateKeyToPem(keys.privateKey)
    };
};

// Criptografia (usando RSA-OAEP)
const encrypt = (publicKey, plaintext) => {
    // publicKey deve ser um objeto forge.pki.PublicKey
    // plaintext deve ser uma string
    const encrypted = publicKey.encrypt(plaintext, "RSA-OAEP");
    return forge.util.encode64(encrypted); // Retorna em Base64 para facilitar o transporte
};

// Decriptografia (usando RSA-OAEP)
const decrypt = (privateKey, encryptedBase64) => {
    // privateKey deve ser um objeto forge.pki.PrivateKey
    // encryptedBase64 deve ser uma string Base64
    const encryptedBytes = forge.util.decode64(encryptedBase64);
    return privateKey.decrypt(encryptedBytes, "RSA-OAEP"); // Retorna a string original
};

// Assinatura (SHA256)
const sign = (privateKey, message) => {
    // privateKey deve ser um objeto forge.pki.PrivateKey
    // message deve ser uma string (ou Buffer, mas string é comum para dados)
    const md = forge.md.sha256.create();
    md.update(message, 'utf8');
    const signatureBytes = privateKey.sign(md);
    return forge.util.encode64(signatureBytes); // Retorna assinatura em Base64
};

// Verificação de Assinatura
const verify = (publicKey, message, signatureBase64) => {
    // publicKey deve ser um objeto forge.pki.PublicKey
    // message deve ser uma string (a mesma que foi usada para assinar)
    // signatureBase64 deve ser a assinatura em Base64
    const md = forge.md.sha256.create();
    md.update(message, 'utf8');
    const signatureBytes = forge.util.decode64(signatureBase64);
    return publicKey.verify(md.digest().bytes(), signatureBytes);
};

module.exports = {
    generateKeyPair,
    encrypt,
    decrypt,
    sign,
    verify
};
