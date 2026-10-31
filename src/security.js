import {b64u_decode , b64u_encode} from "./base64url_converter.js";
import { createHmac , timingSafeEqual } from 'node:crypto';


export function sign(header , payload , secretHex){
    const headerEncoded = b64u_encode(header);
    const payloadEncoded =b64u_encode(payload);
    const signingKey =  `${headerEncoded}.${payloadEncoded}`;

    const signature = createHmac('sha256' , Buffer.from(secretHex, "hex"))
    .update(signingKey)
    .digest()
    .toString('base64url');
    return `${headerEncoded}.${payloadEncoded}.${signature}`;
}


export function verify(token , secretHex){
    const tokenParts =  token.split('.');
    if (tokenParts.length !== 3) return "BAD";


    const [header, payload, signature] = tokenParts;
    const signinginput = `${header}.${payload}`;

    const expected = createHmac("sha256",Buffer.from(secretHex, "hex"))
    .update(signinginput)
    .digest();
    const actual = Buffer.from(signature, "base64url");

    if(timingSafeEqual(actual,expected)){
        return 'OK'
    }
    return "BAD";

}