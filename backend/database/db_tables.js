// BANCO DE DADOS ----------------------------------------------------------------------------------------------------------------------------------------------------------------

const createUsersTable = async (pool) => {
    const createTableQuery = `
      CREATE TABLE IF NOT EXISTS users (
        user_id SERIAL,
        name TEXT NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        user_name VARCHAR(20) PRIMARY KEY,
        password TEXT NOT NULL,
        profile_pic bytea,
        certificate TEXT NOT NULL
      );
  
      CREATE TABLE IF NOT EXISTS users_friends (
      friend1 VARCHAR(20),
      friend2 VARCHAR(20),
      PRIMARY KEY (friend1, friend2),
      friendship BOOLEAN NOT NULL
      );
  
      CREATE TABLE IF NOT EXISTS messages (
      friend1 VARCHAR(20),
      friend2 VARCHAR(20),
      dateTime TEXT,
      PRIMARY KEY (friend1, friend2, dateTime),
      content TEXT
      );
      
      CREATE TABLE IF NOT EXISTS answered_requests (
      friend1 VARCHAR(20),
      friend2 VARCHAR(20),
      PRIMARY KEY (friend1, friend2),
      accepted BOOLEAN
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