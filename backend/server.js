require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bodyParser = require('body-parser');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const createUsersTable = require('./database/db_tables.js');
const diffie_hellman = require('./cryptography/diffie_hellman.js');
const { blowfish } = require('./cryptography/blowfish.js')
const app = express();
const server = http.createServer(app);
const hostname = '0.0.0.0'; 
const io = socketIo(server);
app.use(cors());
app.use(bodyParser.json());

let onlineUsers = {}

const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});

const JWT_SECRET = process.env.JWT_SECRET;

// WEBSOCKET PARA MENSAGENS CHAT SEGURO ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  
io.on('connection', (socket) => {
  console.log('Novo usuário conectado: ', socket.id);

  //CRIPTOGRAFIA-----------------------------------------------------------------------------------------------------------

  // compartilhamento de chaves servidor-usuário naquela sessão
  socket.on('diffie-hellman', (p,g,userPublicKey, callback) => {
    console.log("//Diffie Hellman------------------------------------\n")
    const diffieData = {
      p_value:p,
      g_value: g,
      publicKeyUser: userPublicKey
    };
    console.log("Dados Diffie-Hellman Usuário: ", diffieData);
    
    try{
      const  serverPublicKey = diffie_hellman.startDH(socket.id, p, g, userPublicKey);
      console.log("+Relação socket-id: chaves compartilhadas+\n",diffie_hellman.diffieHellmanSharedKeysUsers);
      callback({success: true, PublicKeyServer: serverPublicKey });
    }
    catch (error) {
      console.error('Erro ao fazer DH: ', error);
      callback({success:false});
    }
  });

  // Quando um usuário se conecta, armazene o usuário e o socket
  socket.on('online-loged', async (user_nameEncrypted, callback) => {
    try{
      const sharedSecret = diffie_hellman.diffieHellmanSharedKeysUsers[socket.id];
      const user_name = blowfish.decrypt(user_nameEncrypted, sharedSecret, {cipherMode: 0, outputType: 0});

      onlineUsers[user_name] = socket.id;
      console.log(`Usuário ${user_name} está online com ID de socket: ${socket.id}`);
      
      callback({ 
        success: true, 
        message: 'Recuperando dados recebidos enquanto estava offline',
        offlineReceivedMessages: blowfish.encrypt(await getOfflineMessages(user_name),sharedSecret, {cipherMode: 0, outputType: 0}),         //lista criptografada
        offlineFriendRequests: blowfish.encrypt(await getPendingFriendRequests(user_name),sharedSecret, {cipherMode: 0, outputType: 0}),     //listas criptografada
        offlineAcceptedRequests: blowfish.encrypt(await getAcceptedFriendRequests(user_name), sharedSecret, {cipherMode: 0, outputType: 0})  //listas criptografada
      });
    }
    catch(error){
      callback({ success:false, message: 'Erro ao recuperar dados recebidos enquanto estava offline: ', erro:error});
    }
    
  });

  // usuario desconectado
  socket.on('disconnected', () => {
    try{
      delete onlineUsers[disconnectedUser];}
    catch{
      console.log("Usuário não estava logado")
    }
    try{
      delete diffie_hellman.diffieHellmanSharedKeysUsers[socket.id];
    }
    catch{
      console.log("Usuário não fez troca de chaves com servidor")
    }
    console.log(`Usuário ${socket.id} desconectou.`);
  });


  // REGISTRO E LOGIN--------------------------------------------------------------------------------------------------------------------------------------------------

  // Registro de usuários
  socket.on('register', async (nameEncrypted, emailEncrypted, passwordEncrypted, user_nameEncrypted,imageEncrypted, callback) => {
    console.log("//Register user------------------------------------\n")
  try {

    const sharedSecret = diffie_hellman.diffieHellmanSharedKeysUsers[socket.id];
    const name = blowfish.decrypt(nameEncrypted, sharedSecret, {cipherMode: 0, outputType: 0});
    const email = blowfish.decrypt(emailEncrypted, sharedSecret, {cipherMode: 0, outputType: 0});
    const password = blowfish.decrypt(passwordEncrypted, sharedSecret, {cipherMode: 0, outputType: 0});
    const user_name = blowfish.decrypt(user_nameEncrypted, sharedSecret, {cipherMode: 0, outputType: 0});
    const image = blowfish.decrypt(imageEncrypted, sharedSecret, {cipherMode: 0, outputType: 0});

    await pool.query(
      'INSERT INTO users (name, email, password, user_name, profile_pic) VALUES ($1, $2, $3, $4, $5) RETURNING user_id',
      [name, email, password, user_name, image]
    );

    callback({success:true, message: "Usuário registrado com sucesso"});
  } catch (error) {
    console.log(error)
    callback({success:false, message: "Erro no registro de usuário"});
  }
});

// Endpoint de Login
socket.on('login', async (emailEncrypted, passwordEncrypted, callback) => {
  console.log("//Login------------------------------------\n")
  try {
    const sharedSecret = diffie_hellman.diffieHellmanSharedKeysUsers[socket.id];
    const email = blowfish.decrypt(emailEncrypted, sharedSecret, {cipherMode: 0, outputType: 0});
    const password = blowfish.decrypt(passwordEncrypted, sharedSecret, {cipherMode: 0, outputType: 0});
    

    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rowCount === 0) {
      callback({ success: false, message: 'Usuário não encontrado' });
    }
    
    const user = result.rows[0];
    
    // Verifica se a senha fornecida corresponde à senha armazenada
    if (password === user.password) {
      // Se as credenciais forem válidas, envia a resposta de successo ao cliente e as solicitações e mensagens pendentes
      callback({ success: true, message: 'Login realizado com sucesso', user_name: result.user_name, name: result.name, profile_pic: result.profile_pic});
    } else {
      // Senha incorreta
      callback({ success:false, message: 'Credenciais inválidas' });
    }
  } catch (error) {
    console.error(error);
    // Em caso de erro, envia a mensagem de erro através do callback
    callback({ success:false, message: 'Erro ao fazer login', error: error.message });
  }
});


// AMIZADE---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

// Listar usuarios
socket.on('list-users', async (user_nameEncrypted, callback) => {
  console.log("//List users (not friends)------------------------------------\n")
  try {
    const sharedSecret = diffie_hellman.diffieHellmanSharedKeysUsers[socket.id];
    const user_name = blowfish.decrypt(user_nameEncrypted, sharedSecret, {cipherMode: 0, outputType: 0});

    const result = await pool.query(
      'SELECT u.user_name FROM users u WHERE u.user_name != $1 AND u.user_name NOT IN (SELECT CASE WHEN friend1 = $1 THEN friend2 ELSE friend1 END FROM users_friends WHERE (friend1 = $1 OR friend2 = $1) AND (friendship = true OR friendship = false));', 
      [user_name]);

    console.log(result.rows)
    callback({success: true, list: result.rows});
  } catch (error) {
    console.error('Erro ao listar usuários:', error);
    callback({success: false, list:[]});
  }
});


// Solicitar amizade
  socket.on('friend-request', async (user_name1Encrypted, user_name2Encrypted, p_valueEncrypted, g_valueEncrypted, publicKey_friend1Encrypted, callback) => {
    console.log("//Request friendship------------------------------------\n")
    try {

      const sharedSecret = diffie_hellman.diffieHellmanSharedKeysUsers[socket.id];  

      const user_name1 = blowfish.decrypt(user_name1Encrypted, sharedSecret, {cipherMode: 0, outputType: 0});
      const user_name2 = blowfish.decrypt(user_name2Encrypted, sharedSecret, {cipherMode: 0, outputType: 0});
      const p_value = blowfish.decrypt(p_valueEncrypted, sharedSecret, {cipherMode: 0, outputType: 0});
      const g_value = blowfish.decrypt(g_valueEncrypted, sharedSecret, {cipherMode: 0, outputType: 0});
      const publicKey_friend1 = blowfish.decrypt(publicKey_friend1Encrypted, sharedSecret, {cipherMode: 0, outputType: 0});
     
      // Verifica se já existe uma solicitação pendente ou aceita
      const existingRequest = await pool.query(
        'SELECT * FROM users_friends WHERE ((friend1 = $1 AND friend2 = $2) OR (friend1 = $2 AND friend2 = $1)) AND friendship = true',
        [user_name1, user_name2]
      );

      if (existingRequest.rowCount > 0) {
        callback({success: false, message: 'Solicitação já enviada' });
        console.log("Solicitação já enviada")
      }

      // Armazenar solicitacao de amizade no banco de dados
      await pool.query(
        `
        INSERT INTO users_friends (friend1, friend2, friendship)
        VALUES ($1, $2, $3);
        `,
        [user_name1, user_name2,false]
      );

      await pool.query(
        `
        INSERT INTO friends_dh (friend1, friend2, p_value, g_value, publicKey_friend1)
        VALUES ($1, $2, $3, $4, $5);
        `,
        [user_name1, user_name2, p_value, g_value, publicKey_friend1]
      );

      // Notifique o destinatário se ele estiver online
      if (onlineUsers[user_name2]) {
        const recipientSocketId = onlineUsers[user_name2];
        const sharedKeyRecipient = diffie_hellman.diffieHellmanSharedKeysUsers[recipientSocketId];
        // Evento para o destinatário receber pedido de amizade
        io.to(recipientSocketId).emit('receive-friend-request', 
          blowfish.encrypt(user_name1, sharedKeyRecipient, {cipherMode: 0, outputType: 0}),
          blowfish.encrypt(p_value, sharedKeyRecipient, {cipherMode: 0, outputType: 0}),
          blowfish.encrypt(g_value, sharedKeyRecipient, {cipherMode: 0, outputType: 0}),
          blowfish.encrypt(publicKey_friend1, sharedKeyRecipient, {cipherMode: 0, outputType: 0}));
      }
      console.log();
      callback({ success: true, message: 'Solicitação de amizade enviada' });
    } catch (error) {
      callback({ success: false, message: 'Erro ao enviar solicitação de amizade: ', error });
      console.log('Erro ao enviar solicitação de amizade: ', error);
    }
  });

  // Aceitar solicitação
  socket.on('accept-friend', async (user_name1Encrypted, user_name2Encrypted, publicKey_friend2Encrypted, callback) => {
    try {
      const sharedSecret = diffie_hellman.diffieHellmanSharedKeysUsers[socket.id];  
      const user_name1 = blowfish.decrypt(user_name1Encrypted, sharedSecret, {cipherMode: 0, outputType: 0});
      const user_name2 = blowfish.decrypt(user_name2Encrypted, sharedSecret, {cipherMode: 0, outputType: 0});
      const publicKey_friend2 = blowfish.decrypt(publicKey_friend2Encrypted, sharedSecret, {cipherMode: 0, outputType: 0});

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

      await pool.query(
        'UPDATE friends_dh SET publicKey_friend2 = $2 WHERE (friend1 = $1 AND friend2 = $2) OR (friend1 = $2 AND friend2 = $1)',
      [user_name1, user_name2, publicKey_friend2]
    );
       callback({ success: true, message: 'Amizade aceita' });

       if (onlineUsers[user_name1]) {
        // Se o destinatário está online, envie o aceite de amizade diretamente
        const recipientSocketId = onlineUsers[user_name1]
        const sharedKeyRecipient = diffie_hellman.diffieHellmanSharedKeysUsers[recipientSocketId];
        io.to(recipientSocketId).emit('accepted-friendship', 
          blowfish.encrypt(user_name2, sharedKeyRecipient,{cipherMode: 0, outputType: 0}),
          blowfish.encrypt(publicKey_friend2, sharedKeyRecipient,{cipherMode: 0, outputType: 0})
        );
       }
       else{

        const result = await pool.query(
          'SELECT p_value, g_value FROM friends_dh WHERE (friend1 = $1 AND friend2 = $2) OR (friend1 = $2 AND friend2 = $1)',
        [user_name1, user_name2]
        );
        let p_value = result.p_value;
        let g_value = result.g_value;

        await pool.query(
          `
          INSERT INTO accepted_requests (friend1, friend2, p_value, g_value, publicKey_friend2)
          VALUES ($1, $2, $3, $4, $5);
          `,
          [user_name1, user_name2,p_value, g_value, publicKey_friend2]
        );
       }
      } catch (error) {
        console.error('Erro ao aceitar solicitação de amizade:', error);
        callback({ success: false, message: 'Erro ao aceitar solicitação de amizade' });
      }
    });

   // Recusar solicitação 
   socket.on('reject-friend', async (user_name1Encrypted, user_name2Encrypted, callback) => {
    try {
      const sharedSecret = diffie_hellman.diffieHellmanSharedKeysUsers[socket.id];  
      const user_name1 = blowfish.decrypt(user_name1Encrypted, sharedSecret, {cipherMode: 0, outputType: 0});
      const user_name2 = blowfish.decrypt(user_name2Encrypted, sharedSecret, {cipherMode: 0, outputType: 0});

      // Deletar solicitação do banco porque foi rejeitada
      await pool.query(
        'DELETE FROM users_friends WHERE (friend1 = $1 AND friend2 = $2) OR (friend1 = $2 AND friend2 = $1)',
      [user_name1, user_name2]
      );

      await pool.query(
        'DELETE FROM friends_dh WHERE (friend1 = $1 AND friend2 = $2) OR (friend1 = $2 AND friend2 = $1)',
      [user_name1, user_name2]
      );

       callback({ success: true, message: 'Solicitação rejeitada' });
      } catch (error) {
        console.error('Erro ao rejeitar solicitação de amizade:', error);
        callback({ success: false, message: 'Erro ao rejeitar solicitação de amizade' });
      }
    });

  // Listar amigos 
  socket.on('list-friends', async (user_name1Encrypted, callback) => {
    console.log("//List Friends------------------------------------")
    try {
      const sharedSecret = diffie_hellman.diffieHellmanSharedKeysUsers[socket.id];  
      const user_name1 = blowfish.decrypt(user_name1Encrypted, sharedSecret, {cipherMode: 0, outputType: 0})
      const friends = await pool.query(
        'SELECT * FROM users_friends WHERE (friend1 = $1 OR friend2 = $1) AND friendship = true',
        [user_name1]
      );

      if (friends.rowCount>0) {
        console.log(`Amigos de ${user_name1}`,friends.rows)
        callback({success:true, friends: blowfish.encrypt(friends.rows,sharedSecret, {cipherMode: 0, outputType: 0})});  //lista criptografada
      }
      else{
        callback({success: false, friends: 'Sem amigos' });
      }
      } catch (error) {
        console.error('Erro ao listar amigos:', error);
        callback({ success: false, message: 'Erro ao listar amigos:', error });
      }
    });

  // listar amigos online
  socket.on('online-friends', async(user_nameEncrypted, callback) => {
    console.log("//Lista de amigos online-----------------------------------\n")
    const sharedSecret = diffie_hellman.diffieHellmanSharedKeysUsers[socket.id];
    const user_name = blowfish.decrypt(user_nameEncrypted, sharedSecret, {cipherMode: 0, outputType: 0});

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

    console.log('onlineFriends',result.rows);
    callback(blowfish.encrypt(result.rows,sharedSecret, {cipherMode: 0, outputType: 0})); //lista criptografada

  })

    // envio de mensagem
  socket.on('send-message', (sender_user_nameEncrypted,recipient_user_nameEncrypted, timestampEncrypted, message) => {
    console.log("//Send message------------------------------------\n")


    const sharedSecret = diffie_hellman.diffieHellmanSharedKeysUsers[socket.id]; 

    const sender_user_name = blowfish.decrypt(sender_user_nameEncrypted, sharedSecret, {cipherMode: 0, outputType: 0});
    const recipient_user_name = blowfish.decrypt(recipient_user_nameEncrypted, sharedSecret, {cipherMode: 0, outputType: 0});
    const timestamp = blowfish.decrypt(timestampEncrypted, sharedSecret, {cipherMode: 0, outputType: 0});
   
    if (onlineUsers[recipient_user_name]) {
      // Se o destinatário está online, envie a mensagem diretamente
      const recipientSocketId = onlineUsers[recipient_user_name];
      const sharedKeyRecipient = diffie_hellman.diffieHellmanSharedKeysUsers[recipientSocketId];
      // Evento para enviar a mensagem criptografada ao destinatário online
      io.to(recipientSocketId).emit('receive-message', 
        blowfish.encrypt(sender_user_name,sharedKeyRecipient, {cipherMode: 0, outputType: 0}),
        blowfish.encrypt(timestamp, sharedKeyRecipient, {cipherMode: 0, outputType: 0}),
        message);
    } else {
      // Caso o destinatário esteja offline, armazene a mensagem no banco
      console.log(`Usuário ${recipient_user_name} está offline. Armazenando mensagem no banco.`);
      storeOfflineMessage(sender_user_name, recipient_user_name, timestamp, message);
    }
  });

    //GRUPOS-----------------------------------------------------------------------------------


});

// função para armazenar mensagens offline no banco de dados
async function storeOfflineMessage(sender_user_name, recipient_user_name, timestamp, message) {
  await pool.query(
    'INSERT INTO messages (friend1, friend2, datetime, content) VALUES ($1, $2, $3, $4)',
    [sender_user_name, recipient_user_name, timestamp, message]
  );
}

// função para listar mensagens recebidas enquanto estava offline
const getOfflineMessages = async (user_name) => {
  try {
    const result = await pool.query(
      `SELECT * FROM messages WHERE friend2 = $1`, 
      [user_name]
    );

    await pool.query(
      `DELETE FROM messages WHERE friend2 = $1`, 
      [user_name]
    );

    return result.rows;
  } catch (error) {
    console.error('Erro ao recuperar mensagens offline:', error);
    return [];
  }
};

// função para listar solicitações de amizade pendentes
const getPendingFriendRequests = async (user_name) => {
  try {
    const result = await pool.query(
      `SELECT u.friend1, f.p_value, f.g_value, f.publicKey_friend1
      FROM users_friends u
      JOIN friends_dh f ON (u.friend1 = f.friend1 AND u.friend2 = f.friend2)
      WHERE u.friend2 = $1 AND u.friendship = false;`, 
      [user_name]
    );
    return result.rows;
  } catch (error) {
    console.error('Erro ao recuperar solicitações de amizade pendentes:', error);
    return [];
  }
};


// função para listar solicitações de amizade aceitas
const getAcceptedFriendRequests = async (user_name) => {
  try {
    const result = await pool.query(
      `SELECT * FROM accepted_requests WHERE friend2 = $1`, 
      [user_name]
    );

    await pool.query(
      `DELETE FROM accepted_requests WHERE friend2 = $1`, 
      [user_name]
    );
    return result.rows;
  } catch (error) {
    console.error('Erro ao recuperar solicitações de amizade aceitas:', error);
    return [];
  }
};


  createUsersTable(pool)
  const PORT = 3000;
  server.listen(PORT, hostname, () => {
    console.log('Server running');
  
});