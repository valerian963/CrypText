const crypto = require("crypto");

// Geração de Par de Chaves
const generateKeyPair = () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return { publicKey, privateKey };
};

// Criptografia / Decriptografia
const encrypt = (publicKey, plaintext) =>
  crypto.publicEncrypt(publicKey, Buffer.from(plaintext));

const decrypt = (privateKey, encrypted) =>
  crypto.privateDecrypt(privateKey, encrypted);

// Assinatura / Verificação
const sign = (privateKey, message) => {
  const signer = crypto.createSign("sha256");
  signer.update(message);
  signer.end();
  return signer.sign(privateKey, "base64");
};

const verify = (publicKey, message, signature) => {
  const verifier = crypto.createVerify("sha256");
  verifier.update(message);
  verifier.end();
  return verifier.verify(publicKey, signature, "base64");
};

// generateKeyPair().then(keys => {
//   console.log(keys);
// }).catch(err => {
//   console.error(err);
// });

// test
// const createServerKeys = async (pool) => {
// pool.query("SELECT public_key, private_key FROM server LIMIT 1;")
//   .then(res => {
//     let publicKey, privateKey;

//     if (res.rows.length > 0) {
//       publicKey = res.rows[0].public_key;
//       privateKey = res.rows[0].private_key;
//       console.log("Chave pública já existe no banco:");
//       console.log(publicKey);
//     } else {
//       // Gera par de chaves
//       const keys = generateKeyPair();
//       publicKey = keys.publicKey;
//       privateKey = keys.privateKey;

//       // Salva a public e private key no banco
//       pool.query(
//         "INSERT INTO server (public_key, private_key) VALUES ($1, $2)",
//         [publicKey, privateKey]
//       )
//       .then(() => {
//         console.log("Nova chave gerada e salva no banco:");
//         console.log(publicKey, privateKey);
//       })
//       .catch(err => console.error("Erro ao salvar chave:", err));
//     }
//   })
//   .catch(err => console.error("Erro ao buscar chave:", err));
// }

// // Exporta funções
module.exports = {
  generateKeyPair,
  encrypt,
  decrypt,
  sign,
  verify,
  createServerKeys
};
