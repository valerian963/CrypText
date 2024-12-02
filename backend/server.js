require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bodyParser = require('body-parser');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const createUsersTable = require('./database/db_tables.js');
const diffie_hellman = require('./cryptography/diffie_hellman.js');
const blowfish = require('./cryptography/blowfish.js');

const app = express();
const server = http.createServer(app);
const hostname = '0.0.0.0'; 
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

// WEBSOCKET PARA MENSAGENS CHAT SEGURO ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  
  //CRIPTOGRAFIA-----------------------------------------------------------------------------------------------------------

// compartilhamento de chaves servidor-usuário naquela sessão
app.post('/diffie-hellman', (req, res) => {
  const { connectionId, p, g, userPublicKey } = req.body;

  try {
    const serverPublicKey = diffie_hellman.startDH(connectionId, p, g, userPublicKey);
    console.log("+Relação connectionId: chaves compartilhadas+\n", diffie_hellman.diffieHellmanSharedKeysUsers);
    res.json({ success: true, publicKeyServer: serverPublicKey });
  } catch (error) {
    console.error('Erro ao fazer Diffie-Hellman:', error);
    res.status(500).json({ success: false, message: 'Erro ao compartilhar chaves' });
  }
});
  
  // Quando um usuário se conecta e está logado, armazene o usuário e o id de conexão
app.post('/online-loged', async (req, res) => {
  const { user_nameEncrypted, connectionId } = req.body;

  try {
    const sharedSecret = diffie_hellman.diffieHellmanSharedKeysUsers[connectionId];
    const user_name = blowfish.decryptDataBlowfish(user_nameEncrypted, sharedSecret);

    // Marca o usuário como online
    onlineUsers[user_name] = connectionId;

    // Recupera dados offline
    const offlineMessages = await getOfflineMessages(user_name);                        // mensagens individuais
    const offlineFriendRequests = await getPendingFriendRequests(user_name);           // solicitações de amizade
    const offlineAcceptedRequests = await getAcceptedFriendRequests(user_name);       // aceites de solitação para poder calcular a chave compartilhada dos dois amigos

    res.json({
      success: true,
      message: 'Recuperando dados recebidos enquanto estava offline',
      offlineReceivedMessages: blowfish.encryptDataBlowfish(offlineMessages, sharedSecret),
      offlineFriendRequests: blowfish.encryptDataBlowfish(offlineFriendRequests, sharedSecret),
      offlineAcceptedRequests: blowfish.encryptDataBlowfish(offlineAcceptedRequests, sharedSecret),
    });
  } catch (error) {
    console.error('Erro ao recuperar dados offline:', error);
    res.status(500).json({ success: false, message: 'Erro ao recuperar dados offline' });
  }
});

app.post('/disconnect', (req, res) => {
  const { connectionId } = req.body;

  try{
    delete onlineUsers[connectionId];}
  catch{
    console.log("Usuário não estava logado")
  }
  try{
    delete diffie_hellman.diffieHellmanSharedKeysUsers[connectionId];
  }
  catch{
    console.log("Usuário não fez troca de chaves com servidor")
  }
  console.log(`Usuário ${connectionId} desconectou.`);
  res.json({ success: true, message: 'Usuário desconectado' });
});
  

// REGISTRO E LOGIN--------------------------------------------------------------------------------------------------------------------------------------------------

// Registro de usuários
app.post('/register', async (req, res) => {
  const { nameEncrypted, emailEncrypted, passwordEncrypted, user_nameEncrypted, imageEncrypted, connectionId } = req.body;
  console.log("//Registro de usuário------------------------------------\n")
  try {
    const sharedSecret = diffie_hellman.diffieHellmanSharedKeysUsers[connectionId];
    const name = blowfish.decryptDataBlowfish(nameEncrypted, sharedSecret);
    const email = blowfish.decryptDataBlowfish(emailEncrypted, sharedSecret);
    const password = blowfish.decryptDataBlowfish(passwordEncrypted, sharedSecret);
    const user_name = blowfish.decryptDataBlowfish(user_nameEncrypted, sharedSecret);
    const image = blowfish.decryptDataBlowfish(imageEncrypted, sharedSecret);

    await pool.query(
      'INSERT INTO users (name, email, password, user_name, profile_pic) VALUES ($1, $2, $3, $4, $5)',
      [name, email, password, user_name, image]
    );

    res.json({ success: true, message: 'Usuário registrado com sucesso' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Erro ao registrar usuário' });
  }
});

// Endpoint de Login
app.post('/login', async (req, res) => {
  console.log("//Login------------------------------------\n")
  const { emailEncrypted, passwordEncrypted, connectionId } = req.body;
  
  try {
    const sharedSecret = diffie_hellman.diffieHellmanSharedKeysUsers[connectionId];
    const email = blowfish.decryptDataBlowfish(emailEncrypted, sharedSecret);
    const password = blowfish.decryptDataBlowfish(passwordEncrypted, sharedSecret);

    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);

    if (result.rowCount === 0) {
      return res.status(404).json({ success: false, message: 'Usuário não encontrado' });
    }

    const user = result.rows[0];
    // Verifica se a senha fornecida corresponde à senha armazenada
    if (password === user.password) {
      // Gera um token JWT para autenticar futuras requisições
      const token = jwt.sign({ id: user.user_id }, SECRET_KEY, { expiresIn: '1h' });

      // Marca o usuário como online
      onlineUsers[user.user_id] = connectionId;

      res.json({ 
        success: true, 
        token,
        name: blowfish.encryptDataBlowfish(user.name, sharedSecret), 
        user_name: blowfish.encryptDataBlowfish(user.user_name, sharedSecret)
      });
    } else {
      res.status(401).json({ success: false, message: 'Senha inválida' });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Erro ao fazer login' });
  }
});


// AMIZADE---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

// Listar usuarios
socket.on('list-users', async (user_nameEncrypted, callback) => {
  console.log("//List users (not friends)------------------------------------\n")
  try {
    const sharedSecret = diffie_hellman.diffieHellmanSharedKeysUsers[socket.id];
    const user_name = blowfish.decryptDataBlowfish(user_nameEncrypted, sharedSecret);

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

app.get('/users', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;

  // Extrai o token do cabeçalho
  const token = authHeader && authHeader.split(" ")[1];
    if (verifyToken(token)){
      const decoded = jwt.verify(token, 'your-secret-key');
      
      const user_name = req.user.user_name;
      const result = await pool.query(
        'SELECT u.user_name FROM users u WHERE u.user_name != $1 AND u.user_name NOT IN (SELECT CASE WHEN friend1 = $1 THEN friend2 ELSE friend1 END FROM users_friends WHERE (friend1 = $1 OR friend2 = $1) AND (friendship = true OR friendship = false));',
        [user_name]
      );
      res.json({ success: true, list: result.rows });
    }else{
      res.status(401).json({ error: 'Invalid token' });
    }
  } catch (error) {
    console.error('Erro ao listar usuários:', error);
    res.status(400).json({ success: false, message: 'Erro ao listar usuários' });
  }
});

function verifyToken(token) {
if (!token) return res.status(401).json({ error: 'Access denied' });
try {
 const decoded = jwt.verify(token, 'your-secret-key');
 req.userId = decoded.userId;
 next();
 } catch (error) {
 
 }
 };



// Solicitar amizade
  socket.on('friend-request', async (user_name1Encrypted, user_name2Encrypted, p_valueEncrypted, g_valueEncrypted, publicKey_friend1Encrypted, callback) => {
    console.log("//Request friendship------------------------------------\n")
    console.log('Texto criptografado:', encryptedData); 
    try {

      const sharedSecret = diffie_hellman.diffieHellmanSharedKeysUsers[socket.id];  

      const user_name1 = blowfish.decryptDataBlowfish(user_name1Encrypted, sharedSecret);
      const user_name2 = blowfish.decryptDataBlowfish(user_name2Encrypted, sharedSecret);
      const p_value = blowfish.decryptDataBlowfish(p_valueEncrypted, sharedSecret);
      const g_value = blowfish.decryptDataBlowfish(g_valueEncrypted, sharedSecret);
      const publicKey_friend1 = blowfish.decryptDataBlowfish(publicKey_friend1Encrypted, sharedSecret);
     
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
          blowfish.encryptDataBlowfish(user_name1, sharedKeyRecipient),
          blowfish.encryptDataBlowfish(p_value, sharedKeyRecipient),
          blowfish.encryptDataBlowfish(g_value, sharedKeyRecipient),
          blowfish.encryptDataBlowfish(publicKey_friend1, sharedKeyRecipient));
      }
      console.log();
      callback({ success: true, message: 'Solicitação de amizade enviada' });
    } catch (error) {
      callback({ success: false, message: 'Erro ao enviar solicitação de amizade: ', error });
      console.log('Erro ao enviar solicitação de amizade: ', error);
    }
  });



app.get('/notifications', authenticateToken, async (req, res) => {
  const user_name = req.user.user_name;

  try {
      // Busca notificações pendentes para o usuário
      const friendRequests = await pool.query(
          'SELECT friend1, p_value, g_value, publicKey_friend1 FROM friends_dh WHERE friend2 = $1',
          [user_name]
      );

      if (friendRequests.rowCount === 0) {
          return res.status(200).json({ notifications: [] });
      }

      // Retorna as notificações encontradas
      res.status(200).json({ notifications: friendRequests.rows });
  } catch (error) {
      console.error('Erro ao buscar notificações:', error);
      res.status(500).json({ message: 'Erro interno do servidor' });
  }
});


  // Aceitar solicitação
  socket.on('accept-friend', async (user_name1Encrypted, user_name2Encrypted, publicKey_friend2Encrypted, callback) => {
    console.log('Texto criptografado:', encryptedData); 
    try {
      const sharedSecret = diffie_hellman.diffieHellmanSharedKeysUsers[socket.id];  
      const user_name1 = blowfish.decryptDataBlowfish(user_name1Encrypted, sharedSecret);
      const user_name2 = blowfish.decryptDataBlowfish(user_name2Encrypted, sharedSecret);
      const publicKey_friend2 = blowfish.decryptDataBlowfish(publicKey_friend2Encrypted, sharedSecret);

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
        io.to(recipientSocketId).emit('accepted-friendship', blowfish.encryptDataBlowfish({ friend2: user_name2, 'publicKey_friend2': publicKey_friend2 }, sharedKeyRecipient));
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
      const user_name1 = blowfish.decryptDataBlowfish(user_name1Encrypted, sharedSecret);
      const user_name2 = blowfish.decryptDataBlowfish(user_name2Encrypted, sharedSecret);

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
      const user_name1 = blowfish.decryptDataBlowfish(user_name1Encrypted, sharedSecret)
      const friends = await pool.query(
        'SELECT * FROM users_friends WHERE (friend1 = $1 OR friend2 = $1) AND friendship = true',
        [user_name1]
      );

      if (friends.rowCount>0) {
        console.log(`Amigos de ${user_name1}`,friends.rows)
        callback({success:true, friends: blowfish.encryptDataBlowfish(friends.rows,sharedSecret)});  //lista criptografada
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
    const user_name = blowfish.decryptDataBlowfish(user_nameEncrypted, sharedSecret);

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
    callback(blowfish.encryptDataBlowfish(result.row,sharedSecret)); //lista criptografada

  })

    // envio de mensagem
  socket.on('send-message', (sender_user_nameEncrypted,recipient_user_nameEncrypted, timestampEncrypted, message) => {
    console.log("//Send message------------------------------------\n")
    console.log('Texto criptografado:', encryptedData); 

    const sharedSecret = diffie_hellman.diffieHellmanSharedKeysUsers[socket.id]; 

    const sender_user_name = blowfish.decryptDataBlowfish(sender_user_nameEncrypted, sharedSecret);
    const recipient_user_name = blowfish.decryptDataBlowfish(recipient_user_nameEncrypted, sharedSecret);
    const timestamp = blowfish.decryptDataBlowfish(timestampEncrypted, sharedSecret);
   
    if (onlineUsers[recipient_user_name]) {
      // Se o destinatário está online, envie a mensagem diretamente
      const recipientSocketId = onlineUsers[recipient_user_name];
      const sharedKeyRecipient = diffie_hellman.diffieHellmanSharedKeysUsers[recipientSocketId];
      // Evento para enviar a mensagem criptografada ao destinatário online
      io.to(recipientSocketId).emit('receive-message', 
        blowfish.encryptDataBlowfish(sender_user_name,sharedKeyRecipient),
        blowfish.encryptDataBlowfish(timestamp, sharedKeyRecipient),
        message);
    } else {
      // Caso o destinatário esteja offline, armazene a mensagem no banco
      console.log(`Usuário ${recipient_user_name} está offline. Armazenando mensagem no banco.`);
      storeOfflineMessage(sender_user_name, recipient_user_name, timestamp, message);
    }
  });

    //GRUPOS-----------------------------------------------------------------------------------



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