const saltSize = 8 // 32 bytes salt
const iterations = 10000
const hash = CryptoJS.algo.SHA512

var cstmFormatter = {
    stringify: function (cipherParams) {
        return cipherParams.salt.clone().concat(cipherParams.ciphertext).toString(CryptoJS.enc.Base64)
    },
    parse: function (saltIvCiphertextB64) {
        const ivSize = 4;
        var saltIvCiphertextWA = CryptoJS.enc.Base64.parse(saltIvCiphertextB64)
        var saltIvWA = CryptoJS.lib.WordArray.create(saltIvCiphertextWA.words.slice(0, saltSize + ivSize), (saltSize + ivSize) * 4)
        var ciphertextWA = CryptoJS.lib.WordArray.create(saltIvCiphertextWA.words.slice(saltSize + ivSize), saltIvCiphertextWA.sigBytes - (saltSize + ivSize) * 4)
        var encryptedCP = CryptoJS.lib.CipherParams.create({ciphertext: ciphertextWA, salt: saltIvWA})
        return encryptedCP
    }
}

var cstmKdf = {
    execute: (password, keySize, ivSize, saltIvWA, hasher) => {
        if (saltIvWA === undefined){ // encrypt
            saltIvWA = CryptoJS.lib.WordArray.random((saltSize + ivSize) * 4);
        }
        var saltWA = CryptoJS.lib.WordArray.create(saltIvWA.words.slice(0, saltSize), saltSize*4)
        var ivWA = CryptoJS.lib.WordArray.create(saltIvWA.words.slice(saltSize, saltSize + ivSize), ivSize*4)
        var keyWA = CryptoJS.PBKDF2(password, saltWA, {keySize: keySize, iterations: iterations, hasher: hash});
        return {key: keyWA, salt: saltIvWA, iv: ivWA};         
    } 
}

var cfg = {
    format: cstmFormatter, 
    kdf: cstmKdf
};

var passphrase = 'some passphrase'
var ciphertextB64  = CryptoJS.AES.encrypt('The quick brown fox jumps over the lazy dog', passphrase, cfg).toString(); // applies cstmFormatter#stringify() and cstmKdf
var decryptedWA = CryptoJS.AES.decrypt(ciphertextB64, passphrase, cfg) // applies cstmFormatter#parse() and cstmKdf
console.log('ciphertextB64:', ciphertextB64)
console.log('decrypted:    ', decryptedWA.toString(CryptoJS.enc.Utf8))
