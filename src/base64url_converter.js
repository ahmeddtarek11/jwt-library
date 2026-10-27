import {Buffer} from 'node:buffer' 

export function b64u_encode (str){
    const encoded = Buffer.from(str , 'utf8').toString('base64url');
    return encoded;
           
}

export function b64u_decode(str){
    const decoded = Buffer.from(str , 'base64url').toString();
    return decoded;
}