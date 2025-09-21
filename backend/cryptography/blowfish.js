const forge = require('node-forge');

const BLOWFISH_KEY_SIZE_BITS = 128; // Exemplo de tamanho de chave (128 bits = 16 bytes)

// Gera uma chave Blowfish aleatória em bytes
const generateKey = () => {
    return forge.random.getBytesSync(BLOWFISH_KEY_SIZE_BITS / 8); // Retorna bytes
};

// Criptografia Blowfish
const encrypt = (plaintext, keyBytes) => { // Removi 'options', pois o IV é gerado aqui
    // Gera um IV random para esta operação
    const iv = forge.random.getBytesSync(8); // Blowfish usa IV de 8 bytes
    const cipher = forge.cipher.createCipher('Blowfish', keyBytes);
    cipher.start({ iv: iv });
    cipher.update(forge.util.createBuffer(plaintext, 'utf8'));
    cipher.finish();
    
    // Retorna o IV seguido do ciphertext, tudo codificado em Base64 para transporte
    return forge.util.encode64(iv + cipher.output.getBytes());
};

// Descriptografia Blowfish
const decrypt = (encryptedBase64, keyBytes) => { // Removi 'options'
    const encryptedBytes = forge.util.decode64(encryptedBase64);
    
    // Extrai o IV do início da string de bytes
    const iv = encryptedBytes.substring(0, 8); // Os primeiros 8 bytes são o IV
    const ciphertext = encryptedBytes.substring(8); // O restante é o texto cifrado

    const decipher = forge.cipher.createDecipher('Blowfish', keyBytes);
    decipher.start({ iv: iv });
    decipher.update(forge.util.createBuffer(ciphertext));
    decipher.finish();
    return decipher.output.toString('utf8');
};

module.exports = {
    generateKey,
    encrypt,
    decrypt
};