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

export function encode_header_and_payload(line){
    
    const header =  line.slice(0 ,line.indexOf('|'));
    const payload = line.slice(line.indexOf('|')+1);
    const encoded_header = b64u_encode(header);
    const encoded_payload = b64u_encode(payload);
    return `${encoded_header}.${encoded_payload}`;
}