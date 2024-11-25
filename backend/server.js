require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const { Pool } = require('pg');
const { createDiffieHellman } = require('crypto'); 
const Blowfish = require('blowfish');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const BigInteger = require('big-integer');

const app = express();
const server = http.createServer(app);
const hostname = '0.0.0.0'; 
const io = socketIo(server);
app.use(cors());
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
    
    CREATE TABLE IF NOT EXISTS accepted_requests (
    friend1 VARCHAR(20),
    friend2 VARCHAR(20),
    PRIMARY KEY (friend1, friend2),
    CONSTRAINT fk_friend1 FOREIGN KEY(friend1) REFERENCES users(user_name),
    CONSTRAINT fk_friend2 FOREIGN KEY(friend2) REFERENCES users(user_name),
    p_value TEXT NOT NULL,
    g_value TEXT NOT NULL,
    publicKey_friend2 TEXT NOT NULL
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
  return textoCriptografado.toString('base64')
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
  const dh = createDiffieHellman( p, 'base64', g, 'base64' ); 
  const publicKey = dh.generateKeys('base64'); 
  const privateKey = dh.getPrivateKey('base64');
 
  const sharedKey = dh.computeSecret(otherPublicKey, 'base64', 'base64');
  return { publicKey, privateKey, sharedKey} ; // usada para criptografia Blowfish
};



function modulo(a, b) {
  // Realiza a divisão inteira de a por b
  let quociente = Math.floor(a / b);

  // Subtrai a multiplicação do quociente pela base (b) de a
  return a - (quociente * b);
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



// WEBSOCKET PARA MENSAGENS CHAT PRIVADO ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  
io.on('connection', (socket) => {
  console.log('Novo usuário conectado: ', socket.id);

  // listar usuarios online
  socket.on('online-users', async(callback) => {
    console.log("//Lista de usuários online-----------------------------------\n")

    let list = Object.keys(onlineUsers);

    const result = await pool.query(`
      SELECT u.user_name, u.name 
      FROM users u
      JOIN users_friends uf ON (u.user_name = uf.friend1 OR u.user_name = uf.friend2)
      JOIN user_status us ON u.user_name = us.user_name
      WHERE ((uf.friend1 = $1 AND uf.friend2 != $1) OR 
            (uf.friend2 = $1 AND uf.friend1 != $1))
        AND uf.friendship = TRUE
        AND us.is_online = TRUE
        AND u.user_name = ANY($2)
      `, [list]);

    let send = result.rows;

    console.log('send',send);
    return callback(send);

  })

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
      const  serverPublicKey = startDH(socket.id, p, g, userPublicKey);
      return callback({success: true, PublicKeyServer: serverPublicKey });
    }
    catch (error) {
      console.error('Erro ao fazer DH: ', error);
      return callback({success:false});
    }
  });

  // Quando um usuário se conecta, armazene o usuário e o socket
  socket.on('online-loged', async (user_name, callback) => {
    try{
      onlineUsers[user_name] = socket.id;
      const sharedSecret = diffieHellmanSharedKeysUsers[socket.id];  
      console.log(`Usuário ${user_name} está online com ID de socket: ${socket.id}`);
      return callback({ 
        success: true, 
        message: 'Recuperando dados recebidos enquanto estava offline', 
        offlineMessages:  encryptDataBlowfish(await getOfflineMessages(user_name),sharedSecret), 
        friendRequests: encryptDataBlowfish(await getPendingFriendRequests(user_name),sharedSecret),
        acceptedRequests: encryptDataBlowfish(await getAcceptedFriendRequests(user_name), sharedSecret) 
      });
    }
    catch(error){
      return callback({ success:false, message: 'Erro ao recuperar dados recebidos enquanto estava offline: ', erro:error});
    }
    
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
      io.to(recipientSocketId).emit('receive-message', encryptDataBlowfish({ friend1: sender_user_name, datetime: timestamp, content: message }, sharedKeyRecipient));
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

    callback({success:true, message: "Usuário registrado com sucesso"});
  } catch (error) {
    callback({success:false, message: "Erro no registro de usuário"});
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
      // Se as credenciais forem válidas, envia a resposta de successo ao cliente e as solicitações e mensagens pendentes
      return callback({ success: true, message: 'Login realizado com sucesso', user_name: result.user_name, name: result.name});
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
        callback({success: false, message: 'Solicitação já enviada' });
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
        const sharedKeyRecipient = diffieHellmanSharedKeysUsers[recipientSocketId];
        io.to(recipientSocketId).emit('receive-friend-request', encryptDataBlowfish({friend1: user_name1, p: p_value, g: g_value, "publicKey_friend1": publicKey_friend1}, sharedKeyRecipient));
      }
      console.log();
      callback({ success: true, message: 'Solicitação de amizade enviada' });
    } catch (error) {
      callback({ success: false, message: 'Erro ao enviar solicitação de amizade: ', error });
      console.log('Erro ao enviar solicitação de amizade: ', error);
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

       if (onlineUsers[user_name1]) {
        // Se o destinatário está online, envie o aceite de amizade diretamente
        const recipientSocketId = onlineUsers[user_name1]
        const sharedKeyRecipient = diffieHellmanSharedKeysUsers[recipientSocketId];
        io.to(recipientSocketId).emit('accepted-friendship', encryptDataBlowfish({ friend2: user_name2, 'publicKey_friend2': publicKey_friend2 }, sharedKeyRecipient));
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


  createUsersTable()
  const PORT = 3000;
  server.listen(PORT, hostname, () => {
    console.log('Server running at http://192.168.1.62:3000');
  
});