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

module.exports = {decryptDataBlowfish, encryptDataBlowfish};