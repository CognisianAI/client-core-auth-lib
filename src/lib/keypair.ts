import * as ed from "@noble/ed25519";

import { Sha256 } from "@aws-crypto/sha256-js";

import { sha512 } from '@noble/hashes/sha512';
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

async function doubleSha256(data: string) {
    const hash = new Sha256();
    hash.update(data);
    const result = await hash.digest();
    const hash2 = new Sha256();
    hash2.update(result);
   const finalResult =  await hash2.digest();
    
        return buf2hex(finalResult);
}
export async function seedToPrivateKey(seed: string) {
  const result = await doubleSha256(seed);
    return result;
}

export async function publicKeyFromPrivateKey(privatekey:string) {
    const pubKey = await ed.getPublicKeyAsync(privatekey); // Sync methods below

    return buf2hex(pubKey);
}

function buf2hex(buffer:Uint8Array ) { // buffer is an ArrayBuffer
    return [...new Uint8Array(buffer)]
        .map(x => x.toString(16).padStart(2, '0'))
        .join('');
  }


export async function signMessage(privatekey: string, message: string) {
    const hash = new Sha256();
    hash.update(message);
    const messageHash = await hash.digest();

    
    const signature = ed.sign(messageHash, privatekey);

    return buf2hex(signature);
}


export async function verifySig(message: string, signature: string, pubkey: string) {
    const hash = new Sha256();
    hash.update(message);
    const messageHash = await hash.digest();


    const isValid = ed.verify(signature, messageHash, pubkey);

    return isValid;
    
}