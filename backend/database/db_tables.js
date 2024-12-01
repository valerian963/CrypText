// BANCO DE DADOS ----------------------------------------------------------------------------------------------------------------------------------------------------------------
const createUsersTable = async (pool) => {
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

  module.exports = createUsersTable;