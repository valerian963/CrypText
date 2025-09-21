require('dotenv').config();
const io = require('socket.io-client');
const forge = require('node-forge');
const pki = forge.pki;

// Importar módulos necessários para o cliente
const rsa = require('C:/Users/Dialog/Documents/topicos_cripto/CrypText/backend/cryptography/rsa.js');
const certificates = require('C:/Users/Dialog/Documents/topicos_cripto/CrypText/backend/certificates/digital_certificate.js');

// --- MODIFICAÇÃO 1: Ajuste na importação do Blowfish ---
// O arquivo blowfish.js anexo exporta um objeto `{ blowfish: ... }`.
// Portanto, precisamos extrair a propriedade 'blowfish' para usar as funções.
const { blowfish } = require('C:/Users/Dialog/Documents/topicos_cripto/CrypText/backend/cryptography/blowfish.js');

// Dados de teste para o registro
const userData = {
    name: "Alice",
    email: "alice@example.com",
    password: "securepassword123",
    user_name: "alice_crypto",
    image: "base64image_data_alice"
};

// Conecta ao servidor Socket.IO
const socket = io('http://127.0.0.1:3000');

// --- MODIFICAÇÃO 2: Função para gerar chave Blowfish ---
// A biblioteca blowfish.js fornecida não tem um gerador de chaves.
// Ela espera uma string como chave. Esta função cria uma chave de teste.
function generateBlowfishKey(length = 16) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
}

socket.on('connect', async () => {
    console.log('Conectado ao servidor Socket.IO');

    try {
        // --- 1. Geração das chaves do usuário e certificado ---
        const { caCert, caPrivateKey } = certificates.loadOrCreateCA(); // A CA do servidor

        // Gerar chaves e certificado para o usuário Alice, assinado pela CA
        const { userCert, userPrivateKey, userCertPem, userPrivateKeyPem } = certificates.generateUserCertificate(
            userData.user_name,
            caCert,
            caPrivateKey
        );
        console.log("Certificado de usuário Alice gerado e assinado pela CA.");

        // --- 2. Geração da Chave Blowfish e Criptografia Híbrida ---
        // --- MODIFICAÇÃO 3: Usando a nova função para gerar a chave ---
        const blowfish_key = generateBlowfishKey(); // Gera uma chave Blowfish como string
        console.log("Chave Blowfish gerada:", blowfish_key);

        // Criptografar a chave Blowfish com a chave pública RSA do servidor (CA)
        const { caPublicKey } = certificates.loadOrCreateCA();
        const blowfish_keyEncrypted = rsa.encrypt(caPublicKey, blowfish_key);
        console.log("Chave Blowfish criptografada com a chave pública da CA.");

        // Criptografar os dados do usuário com a chave Blowfish
        // As opções { cipherMode: 0, outputType: 0 } correspondem a ECB e Base64, respectivamente.
        const nameEncrypted = blowfish.encrypt(userData.name, blowfish_key, { cipherMode: 0, outputType: 0 });
        const emailEncrypted = blowfish.encrypt(userData.email, blowfish_key, { cipherMode: 0, outputType: 0 });
        const passwordEncrypted = blowfish.encrypt(userData.password, blowfish_key, { cipherMode: 0, outputType: 0 });
        const user_nameEncrypted = blowfish.encrypt(userData.user_name, blowfish_key, { cipherMode: 0, outputType: 0 });
        const imageEncrypted = blowfish.encrypt(userData.image, blowfish_key, { cipherMode: 0, outputType: 0 });
        console.log("Dados do usuário criptografados com Blowfish.");


        // --- 3. Geração da Assinatura Digital ---
        const dataToSign = JSON.stringify({
            name: userData.name,
            email: userData.email,
            password: userData.password,
            user_name: userData.user_name,
            image: userData.image
        });

        // Assinar os dados com a chave PRIVADA do usuário
        const signatureBase64 = rsa.sign(userPrivateKey, dataToSign);
        console.log("Dados do usuário assinados com a chave privada de Alice.");


        // --- 4. Envio dos dados para o registro ---
        socket.emit('register',
            nameEncrypted,
            emailEncrypted,
            passwordEncrypted,
            user_nameEncrypted,
            imageEncrypted,
            blowfish_keyEncrypted,
            userCertPem, // Certificado do usuário em PEM
            signatureBase64, // Assinatura digital
            (response) => {
                console.log('Resposta do registro:', response);
                if (response.success) {
                    console.log('Teste de registro bem-sucedido!');
                } else {
                    console.error('Teste de registro falhou:', response.message);
                }
                socket.disconnect(); // Desconecta após o teste
            }
        );

    } catch (error) {
        console.error('Erro durante o teste de registro:', error);
        socket.disconnect();
    }
});

socket.on('disconnect', () => {
    console.log('Desconectado do servidor.');
});

socket.on('connect_error', (err) => {
    console.error('Erro de conexão ao servidor Socket.IO:', err.message);
});