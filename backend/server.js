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
const { blowfish } = require('./cryptography/blowfish.js'); 
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
  socket.on('register', async (nameEncrypted, emailEncrypted, passwordEncrypted, user_nameEncrypted, imageEncrypted, blowfish_keyEncrypted, certificate, signature , callback) => {
    try {
      console.log('Dados recebidos criptografados: ');
      console.log({name_value:nameEncrypted, email_value: emailEncrypted});

      // Conversão do certificado enviado pelo usuário
      const userCertificate = pki.certificateFromPem(certificate);

      // Verifica se foi assinado pela CA do servidor
      if (!caCert.verify(userCertificate)) {
        callback({ success: false, message: "Certificado inválido! Não assinado pela CA)" });
        return;
      }

      // Extrair chave pública do certificado
      const pubKeyUser = certificates.getPublicKeyFromCert(certificate);

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
      
      // VERIFICAÇÃO da assinatura
      const isValidSignature = rsa.verify(pubKeyUser, dataUsedInHash, signature);

      if (!isValidSignature) {
          callback({ success: false, message: "Assinatura digital inválida!" });
          return;
      }

      // Se tudo der certo, dados salvos no banco de dados e registro concluído
      await pool.query(
        'INSERT INTO users (name, email, password, user_name, profile_pic, certificate) VALUES ($1, $2, $3, $4, $5, $6) RETURNING user_id',
        [name, email, password, user_name, image, certificate]
        );

        callback({ success: true, message: "Sucesso no registro de usuário"});
        return;
    } catch (err) {
      console.error(err);
      callback({ success: false, message: "Erro no registro" });
      return;
    }
  });

   // Evento de login dos usuários
  socket.on('login', async (user_nameEncrypted, passwordEncrypted, blowfish_keyEncrypted, signature , callback) => {
    console.log("//Login------------------------------------\n")
    try {

      const blowfish_key = rsa.decrypt(caPrivateKey, blowfish_keyEncrypted);
      const user_name = blowfish.decrypt(user_nameEncrypted, blowfish_key, {cipherMode: 0, outputType: 0});
      const password = blowfish.decrypt(passwordEncrypted, blowfish_key, {cipherMode: 0, outputType: 0});
      
      const pubKeyUser = await getUserPublicKey(user_name);
      
      console.log('Dados recebidos criptografados: ');
      console.log({username_value: user_nameEncrypted, password_value: passwordEncrypted});
      
      const result = await pool.query('SELECT * FROM users WHERE user_name = $1', [user_name]);
      if (result.rowCount === 0) {
        callback({ success: false, message: 'Usuário não encontrado' });
        return;
      }
      const user = result.rows[0];

      // Verifica se a senha fornecida corresponde à senha armazenada
      if (password === user.password) {
        console.log('Verificacao de senhas: ', password, user.password);
        // Verifica assinatura
        const dataUsedInHash = JSON.stringify({
          user_name: user_name,
          password: password
        });
      
      // VERIFICAÇÃO da assinatura
      if (!rsa.verify(pubKeyUser, dataUsedInHash, signature)) {
          callback({ success: false, message: "Assinatura digital inválida!" });
          return;
      }

        // Se as credenciais e assinatura forem válidas, envia a resposta de successo ao cliente e as solicitações e mensagens pendentes
          onlineUsers[user.user_name] = socket.id;     
          console.log(`Login realizado por usuário ${user.user_name}: ${socket.id}`);
          console.log('Lista de usuários logados online: ', onlineUsers);
          callback({ success: true, message: 'Login realizado com sucesso', 
          user_name: blowfish.encrypt(user.user_name, blowfish_key, {cipherMode: 0, outputType: 0}), 
          name: blowfish.encrypt(user.name, blowfish_key, {cipherMode: 0, outputType: 0}), 
          profile_pic: blowfish.encrypt(user.profile_pic, blowfish_key, {cipherMode: 0, outputType: 0})});
      } else {
        // Senha incorreta
        console.log('Erro no login: Credenciais inválidas');
        callback({ success:false, message: 'Credenciais inválidas' });
        return;
      }
    } catch (error) {
      console.error(error);
      // Em caso de erro, envia a mensagem de erro através do callback
      callback({ success:false, message: 'Erro ao fazer login', error: error.message });
      return;
    }
  });
});

const getUserPublicKey = async (user_name) => {
    try {
    const result = await pool.query(
      `SELECT certificate FROM users WHERE user_name = $1`, 
      [user_name]
    );

    const publicKey = certificates.getPublicKeyFromCert(result.rows[0].certificate);
    console.log('Chave pública do usuário: ', publicKey);

    return publicKey;

  } catch (error) {
    console.error('Erro ao recuperar chave publica:', error);
    return null;
  }
  };


  createUsersTable(pool);
  const PORT = 3000;
  server.listen(PORT, hostname, () => {
    console.log('Server running');
  
});




