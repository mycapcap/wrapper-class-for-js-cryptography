class WrapRSA {

static salt = () => window.crypto.getRandomValues(new Uint8Array(16))

static genIv = () => window.crypto.getRandomValues(new Uint8Array(12))

static subtle = window.crypto.subtle || window.crypto.webkitSubtle

static bytesToArrayBuffer = (bytes) => {
    const bytesAsArrayBuffer = new ArrayBuffer(bytes.length);
    const bytesUint8 = new Uint8Array(bytesAsArrayBuffer);
    bytesUint8.set(bytes);
    return bytesAsArrayBuffer;
  }

// static bufferTo64 = (buf) => {



// static bufferToBase64 = (buffer) => {
//         const binary = String.fromCharCode.apply(null, buffer);
//         return window.btoa(binary);
//    }



static ab2str = (buf) => {
    return window.btoa(String.fromCharCode.apply(null, new Uint8Array(buf)));
}
// static str2ab = (str) => {


//     const buf = new ArrayBuffer(str.length); // 1 byte for each char
//     const bufView = new Uint8Array(buf);
//     for (var i=0, strLen=str.length; i < strLen; i++) {
//     bufView[i] = str.charCodeAt(i);
//     }
//     return buf;
// }

static str2ab = (str) => {
    var binaryString = atob(str);
    var bytes = new Uint8Array(binaryString.length);
    for (var i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
}

static cryptoKToJwk = async (ck) => {

    const jwk = await window.crypto.subtle.exportKey("jwk", ck)

    return Promise.resolve(['d','dp','dq','n','p','q','qi'].reduce((so,p) => {
        if (p in jwk) so[p] = jwk[p]
        return so
    }, {}))

}


static jwkToCryptoK = async (key, alg, scope) => {
    
    const keyJwk = {...key}
    const imported = await window.crypto.subtle.importKey('jwk',keyJwk,alg,true,scope)
    return Promise.resolve(imported)

}

static makeJwk = (common, so) => ({...common,...so}) 

static importSignVerify   = async (so, scope) => {
    
    
            return Promise.resolve(await this.jwkToCryptoK(this.makeJwk({        
                                                        kty: "RSA",
                                                        e: "AQAB",
                                                        alg: "RS256",
                                                        ext: true,
                                                },so),{

                                                            name: "RSASSA-PKCS1-v1_5",
                                                            hash: {name: "SHA-256"}, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
                                                },scope))}

static importRSAO = async (so,scope) => Promise.resolve(await this.jwkToCryptoK(this.makeJwk({        
                                                            kty: "RSA",
                                                            e: "AQAB",
                                                            alg: "RSA-OAEP-256",
                                                            ext: true,
                                                    },so),{

                                                    name: "RSA-OAEP",
                                                    hash: {name: "SHA-256"}, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"

                                                },scope))

static signAlg = {
      name: "RSASSA-PKCS1-v1_5",
      hash: {
        name: "SHA-256"
      },
      modulusLength: 2048,
      extractable: false,
      publicExponent: new Uint8Array([1, 0, 1])
    }

static rsaAlg = {
    name: "RSA-OAEP",
    hash: {name: "SHA-256"},
    publicExponent: new Uint8Array([1, 0, 1]),
    modulusLength: 1024
}
    
static rsaKeygen = async (algo = WrapRSA.rsaAlg, scope = ['wrapKey', 'unwrapKey']) => {
    
    const pair = await WrapRSA.subtle
    .generateKey(
        algo,
        true,
        scope,
    ) 
    
    return Promise.resolve(pair)
}

static aesAlgo = {
                name: "AES-GCM",
                length: 256, //can be  128, 192, or 256
            }
static aesKeygen = async (algo = WrapRSA.aesAlgo) => await WrapRSA.subtle.generateKey(
    algo,
    true, //whether the key is extractable (i.e. can be used in exportKey)
    ["encrypt", "decrypt"] //can "encrypt", "decrypt", "wrapKey", or "unwrapKey"
)


static makeWrapKey = async (pwd, salt = false) => {

    if (!salt) salt = WrapRSA.salt()

    const enc = new TextEncoder();

    const keyMater = await WrapRSA.subtle.importKey(
            "raw",
            enc.encode(pwd),
            { name: "PBKDF2" },
            false,
            ["deriveBits", "deriveKey"],
            );
    
    const wrapKey =  await WrapRSA.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt,
            iterations: 500000,
            hash: "SHA-256",
        },
        keyMater,
        { name: "AES-GCM", length: 256 },
        false,
        ["wrapKey", "unwrapKey"],
        )       


    return Promise.resolve(wrapKey);       
    
    }
    
static keyVal = async () => await WrapRSA.aesKeygen()

static wrapAes = async(aesKey,rsaPub) => {
    try {
        
        return await WrapRSA.subtle.wrapKey(
            "raw", //the export format, must be "raw" (only available sometimes)
            aesKey, //the key you want to wrap, must be able to fit in RSA-OAEP padding
            rsaPub, //the public key with "wrapKey" usage flag
            //these are the wrapping key's algorithm options
            {
                name: "RSA-OAEP",
                // iv: iv,
            }
        )

    } catch (error) {
        
        return {error : 'could not wrap aes key', error}
    }
}

static unWrapAES = async (aes,rsapv) => {


        // console.log('unwrap aes')
        
        // console.log('unwrap aes', aes, rsapv)

        try {
            
        const aesUnwrapped = aes.byteLength ? await WrapRSA.subtle.unwrapKey(
                    "raw", //the import format, must be "raw" (only available sometimes)
                    aes, //the key you want to unwrap
                    rsapv, //the private key with "unwrapKey" usage flag
                    WrapRSA.rsaAlg

                    // {   //these are the wrapping key's algorithm options
                    //     name: "RSA-OAEP",
                    //     modulusLength: 2048,
                    //     publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                    //     hash: {name: "SHA-256"},
                    // }
                    
                    ,
                    WrapRSA.aesAlgo
                    // {   //this what you want the wrapped key to become (same as when wrapping)
                    //     name: "AES-GCM",
                    //     length: 256
                    // }
                    
                    ,
                    false, //whether the key is extractable (i.e. can be used in exportKey)
                    ["encrypt", "decrypt"] //the usages you want the unwrapped key to have
                ) : aes
            return Promise.resolve(aesUnwrapped)
        } catch (error) {
            console.log('error unwrap AES',error)    
        }

            
            }


static AESEncrypt = async (message, aesKey, iv = false) => {

    const enc = new TextEncoder()

    const encIv = iv ? iv : WrapRSA.genIv()

    const encrypted = await WrapRSA.subtle.encrypt(
        {
            name: "AES-GCM", iv : encIv
        },
        aesKey
        , enc.encode(message) 
    )

    return iv ? Promise.resolve(WrapRSA.ab2str(encrypted)) : Promise.resolve({iv : encIv, buf : encrypted})

}

static keyValEncrypt = async (keyVal,userKeys) => await WrapRSA.AESEncrypt (keyVal, userKeys.kv, iv = false)


static hybridEncrypt = async(data, userKeys, dbKey = false) => {


    const aesKey = await WrapRSA.aesKeygen()

    try {
        



        const encryptedObj  = await WrapRSA.AESEncrypt(JSON.stringify(data), aesKey)

        encryptedObj.aes  = await WrapRSA.wrapAes(aesKey,userKeys.wu.pub)
        
        
        // if (keyVal) encryptedObj[dbKey] = await WrapRSA.AESEncrypt(keyVal, userKeys.kv.k, userKeys.kv.iv)
    
    
    
        return Promise.resolve(encryptedObj)    

    } catch (error) {
        console.log('hybrid error',error)
        return Promise.resolve(false)
    }

    

}


static hybridDecrypt = async(encrypted, userKeys, dbKey = false, dbKeyVal = false) => {

    
    
    try {

    // console.log(encrypted.aes,userKeys.wu.privateKey)    

    const decKey = await WrapRSA.unWrapAES(encrypted.aes,userKeys.wu.pv)

    // console.log('decKey',decKey)


        const dec = new TextDecoder('utf-8');

        const decrypted = dec.decode(await WrapRSA.subtle.decrypt(   {
            name: "AES-GCM",
            iv: encrypted.iv, //The initialization vector you used to encrypt
            // additionalData: ArrayBuffer, //The addtionalData you used to encrypt (if any)
            // tagLength: 128, //The tagLength you used to encrypt (if any)
        },
        decKey, //from generateKey or importKey above
        encrypted.buf //ArrayBuffer of the data
        ))
    
        return Promise.resolve(JSON.parse(decrypted))
        
    } catch (error) {
        console.log('hybriddecrypt error',error)
        return Promise.resolve({error : 'hybriddecrypt error', errorObj : error})
    }

}


static test = async(userKeys) => {

    userKeys = {}
    
    const db = await idb.openDB('kapkap', 1, {})
    
    let idbKeys = await db.get('user','k') || false

    // console.log('idbKeys',idbKeys)

    if (idbKeys === false) {

        // console.log('ok in false')

        try {
        const rsaKeys = await WrapRSA.rsaKeygen()

        // console.log(rsaKeys)

        const encryptkeyVal = await WrapRSA.keyVal() 

        // console.log(encryptkeyVal)
            
        const kvIv = WrapRSA.genIv() 
        
        const encryptedkeyVal =  await WrapRSA.wrapAes(encryptkeyVal , rsaKeys.publicKey)

        // console.log('wrappedkeyVal', encryptedkeyVal)
        
        
                const encryptedUserKeys = {
        
                    rsa   :  rsaKeys
                  , keyVal :  encryptedkeyVal
                  , kvIv : kvIv
        
              }
        
        // console.log('encrypteduserkeys', encryptedUserKeys)
        
        await db.put('user',encryptedUserKeys, 'k')
        
        idbKeys = await db.get('user','k')

        } catch (error) {

            console.log('encrypteduserkeys idb save ',error)
        }



        
    }

    userKeys = {

         rsa      :  idbKeys.rsa
        , kvIv : idbKeys.kvIv
      // , index :  encryptkeyVal

  }
    userKeys.kv = await WrapRSA.unWrapAES(idbKeys.keyVal,userKeys.wu.privateKey) 
       
    // console.log('userKeys',userKeys)

    const keyValue = 'testing 1'
    const dbKey = 'id'
    const data = {
        id : keyValue
        , dt : {tot : 'tata' }
        , prop:false }
    const idxVal = data[dbKey]  
     
    try {
            
        const encryptedObj = await WrapRSA.hybridEncrypt({...data}, userKeys,dbKey)
        

        await db.put('wallets', encryptedObj)
              
        
    } catch (error) {
        
        console.log('idb put wallet error',error)
        
    }
    
    const indexToRetrieve = await WrapRSA.AESEncrypt(idxVal, userKeys.kv, userKeys.kvIv)
    
    // console.log('indextoretrieve',indexToRetrieve,idxVal)

    const walletEncrypted = await db.get('wallets',indexToRetrieve)

    // console.log(walletEncrypted)




    const wallet = await WrapRSA.hybridDecrypt(walletEncrypted, userKeys, dbKey, idxVal)
    
    // console.log(wallet)
    
    await idb.unwrap(db).close()

    return Promise.resolve(true)


}

static wrapKey = async(keyToWrap,wrappingKey,iv) => {
        // get the key encryption key


    const wrappedKey = await WrapRSA.subtle.wrapKey(
                    "jwk", //the export format, must be "raw" (only available sometimes)
                    keyToWrap, //the key you want to wrap, must be able to fit in RSA-OAEP padding
                    wrappingKey, //the public key with "wrapKey" usage flag
                    //these are the wrapping key's algorithm options
                    {
                        name: "AES-GCM",
                        iv: iv,
                    }
                )
      
        return Promise.resolve(wrappedKey)
        
      }

      
static unwrapKey = async(wrapped, wrapKey, iv, perm,exportable = false) => {

            // console.log(" LIBB unwrap : ",wrapped)

            try {

                const unwrapped = wrapped.byteLength ?  await WrapRSA.subtle.unwrapKey("jwk", wrapped, wrapKey
                    ,{   
                        name: "AES-GCM",
                        // length: 256,
                        iv : WrapRSA.bytesToArrayBuffer(iv)
                    }
                   ,
                   //this what you want the wrapped key to become (same as when wrapping)
                   WrapRSA.rsaAlg
                //    {
                //        name: "RSA-OAEP",
                //        hash: {name: "SHA-256"},
                //        publicExponent: new Uint8Array([1, 0, 1]),
                //        modulusLength: 4096
                //     }
                    ,
                    exportable, //whether the key is extractable (i.e. can be used in exportKey)
                    perm //the usages you want the unwrapped key to have
                
                )
                    : wrapped
                
                // console.log('unwrapped',unwrapped)
                
                // WrapRSA.subtle.unwrapKey(
                //     "jwk", // import format
                //     wrapped, // ArrayBuffer representing key to unwrap
                //     wrapKey, // CryptoKey representing key encryption key
                //     "AES-GCM", // algorithm identifier for key encryption key
                //     "RSA-OAEP", // algorithm identifier for key to unwrap
                //     true, // extractability of key to unwrap
                //     ["encrypt", "decrypt"], // key usages for key to unwrap
                // )
    
                return Promise.resolve(unwrapped)
                
            } catch (error) {
                
                console.log('unwrap key error',error)
                return Promise.resolve(false)

            }


 

}

static unwrapVSKey = async(wrapped, wrapKey, iv, perm,exportable = false) => {


            try {

                const unwrapped = wrapped.byteLength ?  await WrapRSA.subtle.unwrapKey("jwk", wrapped, wrapKey
                    ,{   
                        name: "AES-GCM",
                        // length: 256,
                        iv : WrapRSA.bytesToArrayBuffer(iv)
                    }
                   ,
                   //this what you want the wrapped key to become (same as when wrapping)
                   WrapRSA.signAlg
                    ,
                    exportable, //whether the key is extractable (i.e. can be used in exportKey)
                    perm //the usages you want the unwrapped key to have
                
                )
                    : wrapped
                
                return Promise.resolve(unwrapped)
                
            } catch (error) {
                
                console.log('unwrapVSKey error', error)
                return Promise.resolve(false)

            }


 

}



// static unwrapVerifSign = async(wrapped,wrapKey) => {

//                     const userKeys = await Promise.all([
//                         //pub 1
//                       await WrapRSA.unwrapKey(wrapped[0][0],wrapKey,wrapped[0][1], ['verify'],true)
//                     , await WrapRSA.unwrapKey(wrapped[1][0],wrapKey,wrapped[1][1], ['sign']) 

//                     ])

//                     // await WrapRSA.test(userKeys)

//                     // return [false,false]   
                    
//                     return Promise.resolve(userKeys)
//                     }


static unwrapVSPair = async(wrapped,wrapKey) => {

                    const userKeys = await Promise.all([
                        //pub 1
                        await WrapRSA.unwrapVSKey(wrapped[0][0],wrapKey,wrapped[0][1], ['verify'],true)
                    , await WrapRSA.unwrapVSKey(wrapped[1][0],wrapKey,wrapped[1][1], ['sign']) 

                    ])

                    // await WrapRSA.test(userKeys)

                    // return [false,false]   
                    
                    return Promise.resolve(userKeys)
                    }




static unwrapPair = async(wrapped,wrapKey) => {

                    const userKeys = await Promise.all([
                        //pub 1
                        await WrapRSA.unwrapKey(wrapped[0][0],wrapKey,wrapped[0][1], ['wrapKey'],true)
                    , await WrapRSA.unwrapKey(wrapped[1][0],wrapKey,wrapped[1][1], ['unwrapKey']) 

                    ])

                    // await WrapRSA.test(userKeys)

                    // return [false,false]   
                    
                    return Promise.resolve(userKeys)
                    }


static encrypt = async(pub, data, dbKey = false) => {
    
    
    try {
        const enc = new TextEncoder();

        // const dec = new TextDecoder("utf-8");


        const dataBuffer = enc.encode(
            (typeof data).toLowerCase() === 'string' ? data : JSON.stringify(data)
            //.replaceAll('"','x22') 
        )

        // console.log('encrypt...',dataBuffer)

        // console.log(pub,data,dbKey)

        const dataEncrypted = await WrapRSA.subtle.encrypt(
            {
                name: "RSA-OAEP",
                //label: Uint8Array([...]) //optional
            },
            pub, //from generateKey or importKey above
            dataBuffer //ArrayBuffer of data you want to encrypt
        )

        // console.log('dataencrypted', dataEncrypted)
        switch (true) {

            case (typeof data).toLowerCase() === 'string' :


                return Promise.resolve( WrapRSA.ab2str(dataEncrypted))

            
            case (typeof data).toLowerCase() === 'object' && dbKey !== false :

                const retData = { data : dataEncrypted }


                retData[dbKey] = await WrapRSA.encrypt(pub,data[dbKey])
                
                // dec.decode(await WrapRSA.subtle.encrypt(
                //             {
                //                 name: "RSA-OAEP",
                //                 //label: Uint8Array([...]) //optional
                //             },
                //             pub, //from generateKey or importKey above
                //             dbKeyBuffer //ArrayBuffer of data you want to encrypt
                //         ))
                // console.log('retdata encrypt', retData)
                return Promise.resolve(retData)

            case (typeof data).toLowerCase() === 'object' :
            default:
    
                return Promise.resolve(dataEncrypted)       
            
        }



    } catch (error) {
        
        console.log('error encrypt', error)

        return Promise.resolve({error : 'error encrypt :' + error})


    }

}                        
 
static decrypt = async(pv, data, dbKey = false) => {

    try {

        const enc = new TextEncoder();
        const dec = new TextDecoder();

       switch (true) {

        case (typeof data).toLowerCase() === 'string':
            const dataBuffer = WrapRSA.str2ab(data)
            const dataDecrypted = dec.decode(await WrapRSA.subtle.decrypt(
                {
                    name: "RSA-OAEP",
                    //label: Uint8Array([...]) //optional
                },
                pv, //from generateKey or importKey above
                dataBuffer //ArrayBuffer of data you want to encrypt
            ))
            return Promise.resolve(dataDecrypted)
            
        case (typeof data).toLowerCase() === 'object' :

            const retData = JSON.parse(
                                // decodeURI(
                                    dec.decode(
                                        await WrapRSA.subtle.decrypt(
                                            {
                                                name: "RSA-OAEP",
                                                //label: Uint8Array([...]) //optional
                                            },
                                            pv, //from generateKey or importKey above
                                            (dbKey ? data.data : data) //ArrayBuffer of data you want to encrypt
                                        )
                                 )
                            // )
                        )

            

            if (dbKey && dbKey in retData) delete retData[dbKey]//retData[dbKey] = await WrapRSA.decrypt(pv,data[dbKey])

            // dec.decode(await WrapRSA.subtle.decrypt(
            //                 {
            //                     name: "RSA-OAEP",
            //                     //label: Uint8Array([...]) //optional
            //                 },
            //                 pv, //from generateKey or importKey above
            //                 dbKeyBuffer //ArrayBuffer of data you want to encrypt
            //             ))


            return retData            

            default:           
            break;
       }     





        // const decrypted = await WrapRSA.subtle.decrypt(
        //     {
        //         name: "RSA-OAEP",
        //         //label: Uint8Array([...]) //optional
        //     },
        //     pv, //from generateKey or importKey above
        //     data //ArrayBuffer of data you want to encrypt
        // )
        // console.log('decrypt uint8 array', new Uint8Array(decrypted));
        
        // return Promise.resolve(decrypted)

    } catch (error) {
        
        console.log('error decrypt', error)

        return Promise.resolve(false)


    }



}  



                        
}