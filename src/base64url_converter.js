import {Buffer} from 'node:buffer' 

export function b64u_encode (str){
    const encoded = Buffer.from(str , 'utf8').toString('base64');
    return encoded
        .replaceAll('+', '-')
        .replaceAll('/', '_')
        .replace(/=+$/, '');;
           
}

export function b64u_decode(str){

    str.replaceAll('-', '+')
        .replaceAll('_', '/')
        .replace('', /=+$/);
    const decoded = Buffer.from(str , 'base64url').toString();
    return decoded;
}