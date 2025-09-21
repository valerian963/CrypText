require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bodyParser = require('body-parser');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const forge = require("node-forge");
const pki = forge.pki;
const createUsersTable = require('./database/db_tables.js');
const rsa = require('./cryptography/rsa.js');
const blowfish = require('./cryptography/blowfish.js');
const certificates = require('./certificates/digital_certificate.js')
const app = express();
const server = http.createServer(app);
const hostname = '0.0.0.0'; 
const io = socketIo(server);
app.use(cors());
app.use(bodyParser.json());

let onlineUsers = {};
// Carrega certificados da CA (servidor)
const {  caCert, caPrivateKey  } = certificates.loadOrCreateCA();

const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});
 
// WEBSOCKET PARA MENSAGENS CHAT SEGURO ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  
io.on('connection', (socket) => {

  console.log('Novo usuário conectado: ', socket.id);
  // REGISTRO E LOGIN--------------------------------------------------------------------------------------------------------------------------------------------------

  // Evento Registro de usuários
  socket.on('register', async (nameEncrypted, emailEncrypted, passwordEncrypted, user_nameEncrypted, imageEncrypted, blowfish_keyEncrypted, certificate, hashEncrypted, callback) => {
    try {
      // Conversão do certificado enviado pelo usuário
      const userCertificate = pki.certificateFromPem(certificate);

      // Verifica se foi assinado pela CA do servidor
      if (!caCert.verify(userCertificate)) {
        return callback({ success: false, message: "Certificado inválido! Não assinado pela CA)" });
      }

      // Extrair chave pública do certificado
      const pubKeyUser = certificates.getUserPublicKey(certificate);

      //  Decifrar a chave Blowfish com a chave privada RSA do servidor
      const blowfish_key = caPrivateKey.decrypt(
        forge.util.decode64(blowfish_keyEncrypted), 
        "RSA-OAEP"
      );

      const name = blowfish.decrypt(nameEncrypted, blowfish_key, {cipherMode: 0, outputType: 0});
      const email = blowfish.decrypt(emailEncrypted, blowfish_key, {cipherMode: 0, outputType: 0});
      const password = blowfish.decrypt(passwordEncrypted, blowfish_key, {cipherMode: 0, outputType: 0});
      const user_name = blowfish.decrypt(user_nameEncrypted, blowfish_key, {cipherMode: 0, outputType: 0});
      const image = blowfish.decrypt(imageEncrypted, blowfish_key, {cipherMode: 0, outputType: 0});

      const dataUsedInHash = JSON.stringify({
      name: name,
      email: email,
      password: password,
      user_name: user_name,
      image: image
    });

      // Decifra o hash com a chave publica RSA do usuario
      const hashUser = rsa.decrypt(pubKeyUser, hashEncrypted);
      
      // VERIFICAÇÃO da assinatura
      const isValidSignature = rsa.verify(userPublicKey, dataUsedInHash, hashUser);

      if (!isValidSignature) {
          return callback({ success: false, message: "Assinatura digital inválida!" });
      }

      // Se tudo der certo, dados salvos no banco de dados e registro concluído
      await pool.query(
        'INSERT INTO users (name, email, password, user_name, profile_pic, certificate) VALUES ($1, $2, $3, $4, $5, $6) RETURNING user_id',
        [name, email, password, user_name, image, certificate]
        );

        callback({ success: true, message: "Sucesso no registro de usuário"});
    } catch (err) {
      console.error(err);
      callback({ success: false, message: "Erro no registro" });
    }
  });
});

  createUsersTable(pool);
  const PORT = 3000;
  server.listen(PORT, hostname, () => {
    console.log('Server running');
  
});


  // const getUserPublicKey = async (user_name) => {
  //   try {
  //   const result = await pool.query(
  //     `SELECT certificate FROM users WHERE user_name = $1`, 
  //     [user_name]
  //   );

  //   result.rows[0].public_key;
  //   console.log('Chave pública do usuário: ', result.rows[0].public_key);

  //   return result.rows[0].public_key;

  // } catch (error) {
  //   console.error('Erro ao recuperar chave publica:', error);
  //   return null;
  // }
  // };
