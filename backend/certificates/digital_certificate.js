const fs = require("fs");
const forge = require("node-forge");

const pki = forge.pki;

// Função para carregar ou registrar novo certificado da CA
function loadOrCreateCA() {
  if (fs.existsSync("ca_cert.pem") && fs.existsSync("ca_key.pem")) {
    const caCertPem = fs.readFileSync("ca_cert.pem", "utf8");
    const caPrivateKeyPem = fs.readFileSync("ca_key.pem", "utf8");
    return {
      caCert: pki.certificateFromPem(caCertPem),
      caPublicKey: caCert.publicKey,
      caPrivateKey: pki.privateKeyFromPem(caPrivateKeyPem),
      caCertPem,
      caPrivateKeyPem
    };
  } else {
    // Cria nova CA
    const keys = pki.rsa.generateKeyPair(2048);
    const cert = pki.createCertificate();
    cert.publicKey = keys.publicKey;
    cert.serialNumber = "01";
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 10);
    cert.setSubject([{ name: "commonName", value: "Cryptext-CA" }]);
    cert.setIssuer(cert.subject.attributes);
    cert.sign(keys.privateKey, forge.md.sha256.create());

    const caCertPem = pki.certificateToPem(cert);
    const caPrivateKeyPem = pki.privateKeyToPem(keys.privateKey);

    fs.writeFileSync("ca_cert.pem", caCertPem);
    fs.writeFileSync("ca_key.pem", caPrivateKeyPem);

    return { 
        caCert: cert, 
        caPrivateKey: keys.privateKey, 
        caPublicKey: cert.publicKey, 
        caCertPem, caPrivateKeyPem };
  }
}

// Função para extrair chave publica de certificado recebido
function getPublicKeyFromCert(certPem) {
  const cert = pki.certificateFromPem(certPem);
  const pubKey = cert.publicKey;
//   return pki.publicKeyToPem(pubKey);
  return pubKey
}