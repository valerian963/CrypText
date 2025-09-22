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
const certificates = require('./certificates/digital_certificate.js');
const { sign } = require('crypto');
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
  socket.on('register', async (nameEncrypted, emailEncrypted, passwordEncrypted, user_nameEncrypted, imageEncrypted, blowfish_keyEncrypted, certificate , callback) => {
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
      console.log(pubKeyUser);
      // VERIFICAÇÃO da assinatura
      const isValidSignature = rsa.verify(pubKeyUser, dataUsedInHash, signature);
      
      if (!isValidSignature) {
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


   // Evento de solicitar lista dos usuários
  socket.on('list-users', async (user_nameEncrypted, blowfish_keyEncrypted, signature , callback) => {
    console.log("//List users (not friends)------------------------------------\n")
    try {

      const blowfish_key = rsa.decrypt(caPrivateKey, blowfish_keyEncrypted);
      const user_name = blowfish.decrypt(user_nameEncrypted, blowfish_key, {cipherMode: 0, outputType: 0});

      const pubKeyUser = await getUserPublicKey(user_name);
      
      // Verifica assinatura
      const dataUsedInHash = JSON.stringify({
        user_name: user_name,
      });
      
      // VERIFICAÇÃO da assinatura
      const isValidSignature = rsa.verify(pubKeyUser, dataUsedInHash, signature);
      
      if (!isValidSignature) {
          callback({ success: false, message: "Assinatura digital inválida!" });
          return;
      }
      console.log('Dados recebidos criptografados: ');
      console.log({user_name_value: user_nameEncrypted});
      console.log('\nDados recebidos descriptografados: ');
      console.log({user_name_value: user_name});
      console.log();

      const result = await pool.query(
        'SELECT u.user_name, u.name, u.email FROM users u WHERE u.user_name != $1 AND u.user_name NOT IN (SELECT CASE WHEN friend1 = $1 THEN friend2 ELSE friend1 END FROM users_friends WHERE (friend1 = $1 OR friend2 = $1) AND (friendship = true OR friendship = false));', 
        [user_name]);

      console.log('Lista de usuários descriptografada: \n',result.rows)
      
      // Cifra a lista de usuários para enviar ao usuário
      for (let i=0;i<result.rowCount;i++){
          result.rows[i]['user_name'] =  blowfish.encrypt(result.rows[i]['user_name'],blowfish_key, {cipherMode: 0, outputType: 0});
          result.rows[i]['name'] =  blowfish.encrypt(result.rows[i]['name'],blowfish_key, {cipherMode: 0, outputType: 0});
          result.rows[i]['email'] =  blowfish.encrypt(result.rows[i]['email'],blowfish_key, {cipherMode: 0, outputType: 0});
      };

      console.log('Lista de usuários criptografada: \n',result.rows)
      callback({success: true, list: result.rows});
  } catch (error) {
      console.error('Erro ao listar usuários:', error);
      callback({success: false, list:[]});
  }});


  // Evento de solicitar amizade
  socket.on('friend-request', async (user_name1Encrypted, user_name2Encrypted, blowfish_keyEncrypted, signature , callback) => {
    console.log("//Friend request------------------------------------\n")
    try {

      const blowfish_key = rsa.decrypt(caPrivateKey, blowfish_keyEncrypted);
      const user_name1 = blowfish.decrypt(user_name1Encrypted, blowfish_key, {cipherMode: 0, outputType: 0});
      const user_name2 = blowfish.decrypt(user_name2Encrypted, blowfish_key, {cipherMode: 0, outputType: 0});
      
      const pubKeyUser = await getUserPublicKey(user_name1);
      const pubKeyUser_recipient = await getUserPublicKey(user_name2);
      
      console.log('Dados recebidos criptografados: ');
      console.log({sender_value: user_name1Encrypted, receiver_value: user_name2Encrypted});
      console.log('\nDados recebidos descriptografados: ');
      console.log({sender_value: user_name1, receiver_value: user_name2});
      console.log();

      // Verifica se já existe uma solicitação pendente ou aceita
      const existingRequest = await pool.query(
        'SELECT * FROM users_friends WHERE ((friend1 = $1 AND friend2 = $2) OR (friend1 = $2 AND friend2 = $1)) AND friendship = true',
        [user_name1, user_name2]
      );
      if (existingRequest.rowCount > 0) {
        callback({success: false, message: 'Solicitação já enviada' });
        console.log("Solicitação já enviada");
        return;
      }

      // Armazenar solicitacao de amizade no banco de dados
      await pool.query(
        `
        INSERT INTO users_friends (friend1, friend2, friendship)
        VALUES ($1, $2, $3);
        `,
        [user_name1, user_name2,false]
      );

      console.log(`Solicitação de amizade de ${user_name1} para ${user_name2}`);
      // Notifique o destinatário se ele estiver online
      if (onlineUsers[user_name2]) {
        const recipientSocketId = onlineUsers[user_name2];
    
        // Evento para enviar ao destinatário o pedido de amizade
        const data_sender = await pool.query(
          'SELECT name, email FROM users WHERE user_name = $1',
          [user_name1]
        );

        // Preciso colocar o hash de assinatura aqui quando o servidor encaminha a solicitação pro usuario também?
        console.log(`Notificando usuário ${user_name2}: da solicitação de amizade de ${user_name1}`);
        io.to(recipientSocketId).emit('receive-friend-request', {
          blowfish: rsa.encrypt(caPrivateKey, blowfish_key),
          user_name: blowfish.encrypt(user_name1, blowfish_key, {cipherMode: 0, outputType: 0}),
          name: blowfish.encrypt(data_sender.rows[0].name, blowfish_key, {cipherMode: 0, outputType: 0}),
          email: blowfish.encrypt(data_sender.rows[0].email, blowfish_key, {cipherMode: 0, outputType: 0}),
          certificate: blowfish.encrypt(data_sender.rows[0].certificate, blowfish_key, {cipherMode: 0, outputType: 0})
        });
      }
      else{
        console.log(`Solicitação do usuário ${user_name1} de amizade de ${user_name2} armazenado no banco de dados`);
      }
      callback({ success: true, message: 'Solicitação de amizade enviada' });
    } catch (error) {
      callback({ success: false, message: 'Erro ao enviar solicitação de amizade: ', error });
      console.log('Erro ao enviar solicitação de amizade: ', error);
    }
  });


  // Evento de aceitar solicitação
  // user_name1 é quem solicitou a amizade
  // user_name2 é quem aceitou a solicitação e chamou esse evento
  socket.on('accept-friend', async (user_name1Encrypted, user_name2Encrypted, blowfish_keyEncrypted, signature , callback) => {
    console.log("//Accept friend------------------------------------\n")
    try {

      const blowfish_key = rsa.decrypt(caPrivateKey, blowfish_keyEncrypted);
      const user_name1 = blowfish.decrypt(user_name1Encrypted, blowfish_key, {cipherMode: 0, outputType: 0});
      const user_name2 = blowfish.decrypt(user_name2Encrypted, blowfish_key, {cipherMode: 0, outputType: 0});
      
      const pubKeyUser = await getUserPublicKey(user_name1);
      const pubKeyUser_sender = await getUserPublicKey(user_name2);
      
      console.log('Dados recebidos criptografados: ');
      console.log({sender_value: user_name1Encrypted, receiver_value: user_name2Encrypted});
      console.log('\nDados recebidos descriptografados: ');
      console.log({sender_value: user_name1, receiver_value: user_name2});

      console.log(`Usuário ${user_name2} aceitou pedido de amizade de ${user_name1}`);
      // Verifica se já existe uma solicitação pendente ou aceita
      const existingRequest = await pool.query(
        'SELECT * FROM users_friends WHERE ((friend1 = $1 AND friend2 = $2) OR (friend1 = $2 AND friend2 = $1)) AND friendship = true',
        [user_name1, user_name2]
      );
      if (existingRequest.rowCount > 0) {
        callback({ success: false, message: 'Solicitação já enviada' });
        return;
      }

      // Alterar estado da solicitacao de amizade no banco de dados para true (aceito)
      await pool.query(
        'UPDATE users_friends SET friendship = $3 WHERE (friend1 = $1 AND friend2 = $2) OR (friend1 = $2 AND friend2 = $1)',
      [user_name1, user_name2,true]
      );

      callback({ success: true, message: 'Amizade aceita', 
        certificate_friend: blowfish.encrypt(pubKeyUser, blowfish_key,{cipherMode: 0, outputType: 0})});

      if (onlineUsers[user_name1]) {
        // Se o destinatário está online, envie o aceite de amizade diretamente
        console.log(`Notificando usuário ${user_name1}: do aceite de amizade de ${user_name2}`);
        const recipientSocketId = onlineUsers[user_name1]
        io.to(recipientSocketId).emit('accepted-friendship', 
          {user_name: blowfish.encrypt(user_name2, blowfish_key,{cipherMode: 0, outputType: 0}),
          certificate_friend: blowfish.encrypt(pubKeyUser_sender, blowfish_key,{cipherMode: 0, outputType: 0},
          )
          });
        }
        else{
        console.log(`Aceite do usuário ${user_name2} para amizade de ${user_name1} armazenado no banco de dados`);
        await pool.query(
          `
          INSERT INTO answered_requests (friend1, friend2, publicKey_friend2, accepted)
          VALUES ($1, $2, $3, $4);
          `,
          [user_name1, user_name2, pubKeyUser_sender, true]
        );
        }
      } catch (error) {
        console.error('Erro ao aceitar solicitação de amizade:', error);
        callback({ success: false, message: 'Erro ao aceitar solicitação de amizade' });
      }
  });


  // Evento de rejeitar solicitação de amizade
  socket.on('reject-friend', async (user_name1Encrypted, user_name2Encrypted, blowfish_keyEncrypted, signature , callback) => {
    console.log("//Reject friend------------------------------------\n")
    try {

      const blowfish_key = rsa.decrypt(caPrivateKey, blowfish_keyEncrypted);
      const user_name1 = blowfish.decrypt(user_name1Encrypted, blowfish_key, {cipherMode: 0, outputType: 0});
      const user_name2 = blowfish.decrypt(user_name2Encrypted, blowfish_key, {cipherMode: 0, outputType: 0});
      
      console.log('Dados recebidos criptografados: ');
      console.log({sender_value: user_name1Encrypted, receiver_value: user_name2Encrypted});
      console.log('\nDados recebidos descriptografados: ');
      console.log({sender_value: user_name1, receiver_value: user_name2});

      console.log(`Usuário ${user_name2} recusou pedido de amizade de ${user_name1}`);

      // Deletar solicitação do banco porque foi rejeitada
      await pool.query(
        'DELETE FROM users_friends WHERE (friend1 = $1 AND friend2 = $2) OR (friend1 = $2 AND friend2 = $1)',
      [user_name1, user_name2]
      );

      if (onlineUsers[user_name1]) {
        // Se o destinatário está online, envie a recusa de amizade diretamente
        console.log(`Notificando usuário ${user_name1}: da recusa de amizade de ${user_name2}`);
        const recipientSocketId = onlineUsers[user_name1]
        io.to(recipientSocketId).emit('refused-friendship', 
          {user_name: blowfish.encrypt(user_name2, caPrivateKey,{cipherMode: 0, outputType: 0})});
        }
      else{
        console.log(`Recusa do usuário ${user_name2} para amizade de ${user_name1} armazenada no banco de dados`);

        await pool.query(
          `
          INSERT INTO answered_requests (friend1, friend2, publicKey_friend2, accepted)
          VALUES ($1, $2, $3, $4);
          `,
          [user_name1, user_name2, "", false]);
      }

        callback({ success: true, message: 'Solicitação rejeitada' });
      } catch (error) {
        console.error('Erro ao rejeitar solicitação de amizade:', error);
        callback({ success: false, message: 'Erro ao rejeitar solicitação de amizade' });
      }
  });

  // Evento de listar amigos
  socket.on('list-friends', async (user_nameEncrypted, blowfish_keyEncrypted, signature , callback) => {
    console.log("//List friends------------------------------------\n")
    try {

      const blowfish_key = rsa.decrypt(caPrivateKey, blowfish_keyEncrypted);
      const user_name = blowfish.decrypt(user_nameEncrypted, blowfish_key, {cipherMode: 0, outputType: 0});
      
      const pubKeyUser = await getUserPublicKey(user_name);

      console.log('Dados recebidos criptografados: ');
      console.log({sender_value: user_nameEncrypted});
      console.log('\nDados recebidos descriptografados: ');
      console.log({sender_value: user_name});

      const friends = await pool.query(
        'SELECT * FROM users_friends WHERE (friend1 = $1 OR friend2 = $1) AND friendship = true',
        [user_name]
      );
      if (friends.rowCount>0) {
        console.log(`Amigos de ${user_name}`,friends.rows)
        callback({success:true, friends: blowfish.encrypt(friends.rows,blowfish_key, {cipherMode: 0, outputType: 0}),
        blowfish: rsa.encrypt(pubKeyUser,blowfish_key)
      });  //lista cifrada
      }
      else{
        callback({success: false, friends: [] });
      }
      } catch (error) {
        console.error('Erro ao listar amigos:', error);
        callback({ success: false, message: 'Erro ao listar amigos:', error });
      }
  });


  // Evento de listar amigos que estão ONLINE
  socket.on('online-friends', async (user_nameEncrypted, blowfish_keyEncrypted, signature , callback) => {
    console.log("//List friends------------------------------------\n")
    try {
      const blowfish_key = rsa.decrypt(caPrivateKey, blowfish_keyEncrypted);
      const user_name = blowfish.decrypt(user_nameEncrypted, blowfish_key, {cipherMode: 0, outputType: 0});
      
      const pubKeyUser = await getUserPublicKey(user_name);

      console.log('Dados recebidos criptografados: ');
      console.log({sender_value: user_nameEncrypted});
      console.log('\nDados recebidos descriptografados: ');
      console.log({sender_value: user_name});

      let list = Object.keys(onlineUsers);
      
      const result = await pool.query(`
        SELECT u.user_name, u.name 
        FROM users u
        JOIN users_friends uf ON (u.user_name = uf.friend1 OR u.user_name = uf.friend2)
        WHERE ((uf.friend1 = $1 AND uf.friend2 != $1) OR 
              (uf.friend2 = $1 AND uf.friend1 != $1))
          AND uf.friendship = TRUE
          AND u.user_name = ANY($2)
        `, [user_name, list]);

      console.log('Lista de amigos online',result.rows);
      callback({success: true, list: blowfish.encrypt(result.rows,blowfish_key, {cipherMode: 0, outputType: 0}),
    blowfish: rsa.encrypt(pubKeyUser,blowfish_key)}); //lista criptografada
    }
    catch(error){
      console.log('Falha ao listar amigos online: ', error);
      callback({success: false}); //lista criptografada
    }
  });

  // Evento de enviar mensagem para amigos
  socket.on('send-message', async (sender_user_nameEncrypted,recipient_user_nameEncrypted, timestampEncrypted, message, blowfish_keyEncrypted, blowfishMessage, signature , callback) => {
    console.log("//Send message------------------------------------\n");
    try {

      const blowfish_key = rsa.decrypt(caPrivateKey, blowfish_keyEncrypted);
      const sender_user_name = blowfish.decrypt(sender_user_nameEncrypted, blowfish_key, {cipherMode: 0, outputType: 0});
      const recipient_user_name = blowfish.decrypt(recipient_user_nameEncrypted, blowfish_key, {cipherMode: 0, outputType: 0});

      const pubKeyUser_recipient = await getUserPublicKey(recipient_user_name);
      
      console.log('Dados recebidos criptografados: ');
      console.log({sender_value: sender_user_nameEncrypted, receiver_value: recipient_user_nameEncrypted,timestamp:timestampEncrypted});
      console.log('\nDados recebidos descriptografados: ');
      console.log({sender_value: sender_user_name, receiver_value: recipient_user_name,timestamp:timestamp});
      console.log();

      if (onlineUsers[recipient_user_name]) {
        // Se o destinatário está online, envie a mensagem diretamente
        console.log(`Usuário ${recipient_user_name} online. Mandando mensagem diretamente`);
        console.log('Lista de usuários logados online: ', onlineUsers);
        const recipientSocketId = onlineUsers[recipient_user_name];

        // Evento para enviar a mensagem criptografada ao destinatário online
        io.to(recipientSocketId).emit('receive-message', 
          {sender: blowfish.encrypt(sender_user_name,pubKeyUser_recipient, {cipherMode: 0, outputType: 0}),
          timestamp:timestampEncrypted,
          blowfish: blowfishMessage,
          content: message,
          signature:signature});
  
      } else {
        // Caso o destinatário esteja offline, armazene a mensagem no banco
        console.log(`Usuário ${recipient_user_name} está offline. Armazenando mensagem no banco.`);
        storeOfflineMessage(sender_user_name, recipient_user_name, timestampEncrypted, message, blowfishMessage, signature);
      }
      callback({success: true}); 
      } catch (error) {
        console.error('Erro ao aceitar solicitação de amizade:', error);
        callback({ success: false, message: 'Erro ao aceitar solicitação de amizade' });
      }
  });
});

const getUserPublicKey = async (user_name) => {
    try {
    const result = await pool.query(
      `SELECT * FROM users WHERE user_name = $1`, 
      [user_name]
    );

    const publicKey = certificates.getPublicKeyFromCert(result.rows[0].certificate);
    console.log('Chave pública do usuário: ', result.rows[0].certificate);

    return publicKey;

  } catch (error) {
    console.error('Erro ao recuperar chave publica:', error);
    return null;
  }
};

// Função para armazenar mensagens offline no banco de dados
async function storeOfflineMessage(sender_user_name, recipient_user_name, timestampEncrypted, message, blowfishMessage, signature) {
  await pool.query(
    'INSERT INTO messages (friend1, friend2, datetime, content, blowfish_key, signature) VALUES ($1, $2, $3, $4, $5, $6)',
    [sender_user_name, recipient_user_name, timestampEncrypted, message, blowfishMessage, signature]
  );
}

  createUsersTable(pool);
  const PORT = 3000;
  server.listen(PORT, hostname, () => {
    console.log('Server running');
  
});




