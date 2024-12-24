const saltSize = 8 // 32 bytes salt
const iterations = 10000
const hash = CryptoJS.algo.SHA512

var cstmFormatter = {
    stringify: function (cipherParams) {
        return cipherParams.salt.clone().concat(cipherParams.ciphertext).toString(CryptoJS.enc.Base64)
    },
    parse: function (saltCiphertextB64) {
        var saltCiphertextWA = CryptoJS.enc.Base64.parse(saltCiphertextB64)
        var saltWA = CryptoJS.lib.WordArray.create(saltCiphertextWA.words.slice(0, saltSize), saltSize * 4)
        var ciphertextWA = CryptoJS.lib.WordArray.create(saltCiphertextWA.words.slice(saltSize), saltCiphertextWA.sigBytes - saltSize * 4)
        var encryptedCP = CryptoJS.lib.CipherParams.create({ciphertext: ciphertextWA, salt: saltWA})
        return encryptedCP
    }
}

var cstmKdf = {
    execute: (password, keySize, ivSize, saltWA, hasher) => {
        if (saltWA === undefined){ // encrypt
        		saltWA = CryptoJS.lib.WordArray.random(saltSize * 4)
        }
        var keyIvWA = CryptoJS.PBKDF2(password, saltWA, {keySize: keySize + ivSize, iterations: iterations, hasher: hash})
        var keyWA = CryptoJS.lib.WordArray.create(keyIvWA.words.slice(0, keySize), keySize * 4)
        var ivWA = CryptoJS.lib.WordArray.create(keyIvWA.words.slice(keySize, keySize + ivSize), ivSize * 4)
        return {key: keyWA, salt: saltWA, iv: ivWA}         
    } 
}

var cfg = {
    format: cstmFormatter, 
    kdf: cstmKdf
}

var passphrase = 'some passphrase'
var ciphertextB64  = CryptoJS.AES.encrypt('The quick brown fox jumps over the lazy dog', passphrase, cfg).toString() // applies cstmFormatter#stringify() and cstmKdf
var decryptedWA = CryptoJS.AES.decrypt(ciphertextB64, passphrase, cfg) // applies cstmFormatter#parse() and cstmKdf
console.log("encryptedB64:", ciphertextB64)
console.log("decrypted:   ", decryptedWA.toString(CryptoJS.enc.Utf8))
