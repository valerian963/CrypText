require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const { Pool } = require('pg');
const { createDiffieHellman } = require('crypto'); 
const Blowfish = require('blowfish');
const http = require('http');
const socketIo = require('socket.io');

const app = express();
const server = http.createServer(app);
const hostname = '0.0.0.0'; 
const io = socketIo(server);
app.use(bodyParser.json());

const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});

let onlineUsers = {}
// guarda as chaves Diffie-Hellman de cada usuário temporariamente
let diffieHellmanSharedKeysUsers = {};


// BANCO DE DADOS ----------------------------------------------------------------------------------------------------------------------------------------------------------------
const createUsersTable = async () => {
  const createTableQuery = `
    CREATE TABLE IF NOT EXISTS users (
      user_id SERIAL,
      name TEXT NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      user_name VARCHAR(20) PRIMARY KEY,
      password TEXT NOT NULL,
      profile_pic bytea
    );

    CREATE TABLE IF NOT EXISTS users_friends (
    friend1 VARCHAR(20),
    friend2 VARCHAR(20),
    PRIMARY KEY (friend1, friend2),
    CONSTRAINT fk_friend1 FOREIGN KEY(friend1) REFERENCES users(user_name),
    CONSTRAINT fk_friend2 FOREIGN KEY(friend2) REFERENCES users(user_name),
    friendship BOOLEAN NOT NULL
    );

    CREATE TABLE IF NOT EXISTS friends_dh (
    friend1 VARCHAR(20),
    friend2 VARCHAR(20),
    PRIMARY KEY (friend1, friend2),
    CONSTRAINT fk_friend1 FOREIGN KEY(friend1) REFERENCES users(user_name),
    CONSTRAINT fk_friend2 FOREIGN KEY(friend2) REFERENCES users(user_name),
    p_value TEXT NOT NULL,
    g_value TEXT NOT NULL,
    publicKey_friend1 TEXT NOT NULL,
    publicKey_friend2 TEXT
    );

    CREATE TABLE IF NOT EXISTS messages (
    friend1 VARCHAR(20),
    friend2 VARCHAR(20),
    dateTime TIMESTAMP,
    PRIMARY KEY (friend1, friend2, dateTime),
    CONSTRAINT fk_friend1 FOREIGN KEY(friend1) REFERENCES users(user_name),
    CONSTRAINT fk_friend2 FOREIGN KEY(friend2) REFERENCES users(user_name),
    content TEXT
    );
  `;
  try {
    await pool.query(createTableQuery);
    console.log('Tabelas verificadas/criadas com successo.');
  } catch (error) {
    console.error('Erro ao criar/verificar tabelas:', error);
  }
};

function cleanJson(jsonString) {
  const jsonLimpo = jsonString.replace(/[^{}[\]_@#!?":,a-zA-Z0-9\s.-]/g, "");

  try {
    const resultado = JSON.parse(jsonLimpo);
    //console.log("JSON válido após limpeza.");
    return resultado;
  } catch (error) {
    console.log("A limpeza falhou ao produzir JSON válido:", error.message);
    return null; // Retorna null se ainda não estiver em um formato válido
  }
}

// CRIPTOGRAFIA ------------------------------------------------------------------------------------------------------------------------
// Função para criptografar dados com Blowfish
const encryptDataBlowfish = (data, key) => {
  const jsonString = JSON.stringify(data);
  const bf = new Blowfish(key);
  const textoCriptografado = bf.encrypt(jsonString);
  console.log('Texto criptografado:', textoCriptografado);    
  return textoCriptografado.toString('hex')
};

// Função para descriptografar dados com Blowfish
const decryptDataBlowfish = (encryptedData, key) => {
  const bf = new Blowfish(key);
  const decryptedString = bf.decrypt(encryptedData);
  console.log('Texto descriptografado:', decryptedString);    
  return (cleanJson(decryptedString));
};

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

// Diffie Hellman - Função para gerar chave compartilhada
function receiveDiffieHellman (p, g, otherPublicKey) {
  const dh = createDiffieHellman( p, 'hex', g, 'hex' ); 
  const publicKey = dh.generateKeys('hex'); 
  const privateKey = dh.getPrivateKey('hex');
 
  const sharedKey = dh.computeSecret(otherPublicKey, 'hex', 'hex');
  return { publicKey, privateKey, sharedKey} ; // usada para criptografia Blowfish
};

function startDH(socketid, p, g, clientPublicKey) {
  const { publicKey, privateKey, sharedKey } = receiveDiffieHellman (p, g, clientPublicKey);

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


// WEBSOCKET PARA MENSAGENS CHAT PRIVADO ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  
io.on('connection', (socket) => {
  console.log('Novo usuário conectado: ', socket.id);

  //CRIPTOGRAFIA-----------------------------------------------------------------------------------------------------------

  // compartilhamento de chaves servidor-usuário naquela sessão
  socket.on('diffie-hellman', (p,g,userPublicKey, callback) => {
    console.log("//Diffie Hellman------------------------------------\n")
    try{
      const  serverPublicKey = startDH(socket.id, p,g,userPublicKey);
      callback({success: true, PublicKeyServer: serverPublicKey });
    }
    catch (error) {
      console.error('Erro ao fazer DH: ', error);
      callback({success:false});
    }
  });

  // Quando um usuário se conecta, armazene o usuário e o socket
  socket.on('online-loged', (user_name) => {
    onlineUsers[user_name] = socket.id;
    console.log(`Usuário ${user_name} está online com ID de socket: ${socket.id}`);
  });

  // usuario desconectado
  socket.on('disconnect', () => {
    const disconnectedUser = Object.keys(onlineUsers).find(user_name => onlineUsers[user_name] === socket.id);
    if (disconnectedUser) {
      delete onlineUsers[disconnectedUser];
      console.log(`Usuário ${disconnectedUser} desconectou.`);
    }
  });

  // envio de mensagem
  socket.on('send-message', (encryptedData) => {
    console.log("//Send message------------------------------------\n")
    console.log('Texto criptografado:', encryptedData); 

    const sharedSecret = diffieHellmanSharedKeysUsers[socket.id];  

    const {sender_user_name,recipient_user_name, timestamp, message} = decryptDataBlowfish(encryptedData, sharedSecret);


    if (onlineUsers[recipient_user_name]) {
      // Se o destinatário está online, envie a mensagem diretamente
      const recipientSocketId = onlineUsers[recipient_user_name];
      const sharedKeyRecipient = diffieHellmanSharedKeysUsers[recipientSocketId];
      // Envia a mensagem criptografada ao destinatário online
      io.to(recipientSocketId).emit('receive-message', encryptDataBlowfish({ sender_user_name, timestamp, message }, sharedKeyRecipient));
    } else {
      // Caso o destinatário esteja offline, armazene a mensagem no banco
      console.log(`Usuário ${recipient_user_name} está offline. Armazenando mensagem no banco.`);
      storeOfflineMessage(sender_user_name, recipient_user_name, timestamp, message);
    }
  });

  // REGISTRO E LOGIN--------------------------------------------------------------------------------------------------------------------------------------------------

  // Registro de usuários
  socket.on('register', async (encryptedData, callback) => {
    console.log("//Register user------------------------------------\n")
    console.log('Texto criptografado:', encryptedData); 
  try {

    const sharedSecret = diffieHellmanSharedKeysUsers[socket.id];  

    const {name, email, password, user_name,image} = decryptDataBlowfish(encryptedData, sharedSecret);

    await pool.query(
      'INSERT INTO users (name, email, password, user_name, profile_pic) VALUES ($1, $2, $3, $4, $5) RETURNING user_id',
      [name, email, password, user_name, image]
    );

    callback({success:true});
  } catch (error) {
    callback({success:false});
  }
});

// Endpoint de Login
socket.on('login', async (encryptedData, callback) => {
  console.log("//Login------------------------------------\n")
  console.log('Texto criptografado:', encryptedData);  
  try {
    const sharedSecret = diffieHellmanSharedKeysUsers[socket.id];
    const decryptedData= decryptDataBlowfish(encryptedData, sharedSecret);

    const result = await pool.query('SELECT * FROM users WHERE email = $1', [decryptedData.email]);
    if (result.rowCount === 0) {
      return callback({ message: 'Usuário não encontrado' });
    }
    
    const user = result.rows[0];
    
    // Verifica se a senha fornecida corresponde à senha armazenada
    if (decryptedData.password === user.password) {
      // Se as credenciais forem válidas, envia a resposta de successo ao cliente
      return callback({ success:true, message: 'Login realizado com successo', userId: user.user_id });
    } else {
      // Senha incorreta
      return callback({ success:false, message: 'Credenciais inválidas' });
    }
  } catch (error) {
    console.error(error);
    // Em caso de erro, envia a mensagem de erro através do callback
    return callback({ success:false, message: 'Erro ao fazer login', error: error.message });
  }
});


// AMIZADE---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

// Listar usuarios
socket.on('list-users', async (user_name, callback) => {
  console.log("//List users (not friends)------------------------------------\n")
  try {
    const result = await pool.query(
      'SELECT u.user_name FROM users u WHERE u.user_name != $1 AND u.user_name NOT IN (SELECT CASE WHEN friend1 = $1 THEN friend2 ELSE friend1 END FROM users_friends WHERE (friend1 = $1 OR friend2 = $1) AND (friendship = true OR friendship = false));', 
      [user_name]);

    console.log(result.rows)
    callback(result.rows);
  } catch (error) {
    console.error('Erro ao listar usuários:', error);
    callback([]);
  }
});


// Solicitar amizade
  socket.on('friend-request', async (encryptedData, callback) => {
    console.log("//Request friendship------------------------------------\n")
    console.log('Texto criptografado:', encryptedData); 
    try {

      const sharedSecret = diffieHellmanSharedKeysUsers[socket.id];  

      const {user_name1, user_name2, p_value, g_value, publicKey_friend1} = decryptDataBlowfish(encryptedData, sharedSecret);

      // Verifica se já existe uma solicitação pendente ou aceita
      const existingRequest = await pool.query(
        'SELECT * FROM users_friends WHERE ((friend1 = $1 AND friend2 = $2) OR (friend1 = $2 AND friend2 = $1)) AND friendship = true',
        [user_name1, user_name2]
      );

      if (existingRequest.rowCount > 0) {
        callback({ success: true, message: 'Solicitação já enviada' });
        console.log("Solicitação já enviada")
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
        io.to(recipientSocketId).emit('receive-friend-request', { user_name1 });
      }
      console.log();
      callback({ success: true, message: 'Solicitação de amizade enviada' });
    } catch (error) {
      callback({ success: true, message: 'Erro ao enviar solicitação de amizade: ', error });
    }
  });

  // Aceitar solicitação
  socket.on('accept-friend', async (encryptedData, callback) => {
    console.log('Texto criptografado:', encryptedData); 
    try {
      const sharedSecret = diffieHellmanSharedKeysUsers[socket.id];  
      const {user_name1, user_name2, publicKey_friend2} = decryptDataBlowfish(encryptedData, sharedSecret);

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
      } catch (error) {
        console.error('Erro ao aceitar solicitação de amizade:', error);
        callback({ success: false, message: 'Erro ao aceitar solicitação de amizade' });
      }
    });

   // Recusar solicitação 
   socket.on('reject-friend', async (encryptedData, callback) => {
    try {
      const sharedSecret = diffieHellmanSharedKeysUsers[socket.id];  
      const {user_name1, user_name2} = decryptDataBlowfish(encryptedData, sharedSecret);

      // Alterar estado da solicitacao de amizade no banco de dados para true (aceito)
      await pool.query(
        'DELETE FROM users_friends WHERE (friend1 = $1 AND friend2 = $2) OR (friend1 = $2 AND friend2 = $1)',
      [user_name1, user_name2,true]
      );

      await pool.query(
        'UPDATE friends_dh SET publicKey_friend2 = $2 WHERE (friend1 = $1 AND friend2 = $2) OR (friend1 = $2 AND friend2 = $1)',
      [user_name1, user_name2, publicKey_friend2]
    );
       callback({ success: true, message: 'Solicitação rejeitada' });
      } catch (error) {
        console.error('Erro ao rejeitar solicitação de amizade:', error);
        callback({ success: false, message: 'Erro ao rejeitar solicitação de amizade' });
      }
    });

  // Listar amigos 
  socket.on('list-friends', async (user_name1, callback) => {
    console.log("//List Friends------------------------------------")
    try {
      const friends = await pool.query(
        'SELECT * FROM users_friends WHERE (friend1 = $1 OR friend2 = $1) AND friendship = true',
        [user_name1]
      );
      const sharedSecret = diffieHellmanSharedKeysUsers[socket.id];  
      if (friends.rowCount>0) {
        callback({success:true, friends: encryptDataBlowfish(friends.rows,sharedSecret)});
      }
      else{
        callback({ success: false, friends: 'Sem amigos' });
      }
      } catch (error) {
        console.error('Erro ao listar amigos:', error);
        callback({ success: false, message: 'Erro ao listar amigos:', error });
      }
    });


});

// função para armazenar mensagens offline no banco de dados
async function storeOfflineMessage(sender_user_name, recipient_user_name, timestamp, message) {
  await pool.query(
    'INSERT INTO messages (friend1, friend2, datetime, content) VALUES ($1, $2, $3, $4)',
    [sender_user_name, recipient_user_name, timestamp, message]
  );
}

  createUsersTable()
  const PORT = 3000;
  server.listen(PORT, hostname, () => {
    console.log('Server running at http://192.168.1.62:3000');
  
});