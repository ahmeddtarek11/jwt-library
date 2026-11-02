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


export function verify(token, secret, keyKind = "oct") {
    const tokenParts =  token.split('.');
    if (tokenParts.length !== 3) return "BAD";


    const [header, payload, signature] = tokenParts;
    const signingInput = `${header}.${payload}`;

    const keyBytes = keyKind === "pub"
      ? Buffer.from(secret, "utf8")
      : Buffer.from(secret, "hex");

    const expected = createHmac("sha256", keyBytes)
      .update(signingInput)
      .digest();
    const actual = Buffer.from(signature, "base64url");

    if (actual.length !== expected.length) return "BAD";

    return timingSafeEqual(actual, expected) ? "OK" : "BAD";

}
export function verifyRs256(token, expectedSignatureHex) {
  const parts = token.split(".");

  if (parts.length !== 3) {
    return "BAD";
  }

  const signatureBytes = Buffer.from(parts[2], "base64url");
  const actualSignatureHex = signatureBytes.toString("hex");

  return actualSignatureHex.toLowerCase() ===
    expectedSignatureHex.toLowerCase()
    ? "OK"
    : "BAD";
}

export function verifyAlg(token , key , keykind){
    const symmetric = ["HS256", "HS384", "HS512"];
    const asymmetric = ["RS256", "RS384", "RS512", "ES256"];
    const parts = token.split(".");
    if (parts.length !== 3) return "REJECTED bad_token";
    let header;

  try {
    header = JSON.parse(b64u_decode(parts[0]));

    if (
      header === null ||
      typeof header !== "object" ||
      Array.isArray(header)
    ) {
      return "REJECTED bad_token";
    }
  } catch {
    return "REJECTED bad_token";
  }


   const tokenAlg = header.alg;

  if (
    !symmetric.includes(tokenAlg) &&
    !asymmetric.includes(tokenAlg)
  ) {
    return "REJECTED bad_alg";
  }

  if (
    (keykind === "oct" && asymmetric.includes(tokenAlg)) ||
    (keykind === "pub" && symmetric.includes(tokenAlg))
  ) {
    return "REJECTED alg_mismatch";
  }

  if (tokenAlg !== "HS256") {
    return "REJECTED bad_alg";
  }

  return verify(token, key, keykind) === "OK"
    ? "OK"
    : "REJECTED bad_signature";
}


export function validateClaims(now , issuer, audience, leeway ,claims){
    if(now > claims["exp"]+leeway) return 'EXPIRED';
    if(now  < claims['nbf']-leeway)return 'NOT_YET_VALID';
    if(claims['iss'] != issuer) return 'BAD_ISS';

    if(claims.aud !== undefined){
        const validAud = Array.isArray(claims.aud) ? 
        claims.aud.includes(audience) : 
        claims.aud == audience;
        
         if(!validAud)return 'BAD_AUD';
    }

    return 'OK';
}

export function verifyWithKeyStore(value , keystore){
      const keyparts =value.split(".");
      if(keyparts.length !== 3) return 'BAD reason=bad_token';


      let decodedHeader ; 
      try{
      decodedHeader = JSON.parse(b64u_decode(keyparts[0]));
      }
      catch{
        return "BAD reason=bad_token";
      }

      if(decodedHeader === null || typeof decodedHeader !== "object" || Array.isArray(decodedHeader))
        return 'BAD reason=bad_token';



      const keyKid = decodedHeader.kid;
      if(keyKid === null  || keyKid=== undefined || !keystore.has(keyKid) ) return "BAD reason=unknown_kid";
      const secretHex =keystore.get(keyKid);
      const signingKey = `${keyparts[0]}.${keyparts[1]}`;
      const signature = createHmac('sha256' , Buffer.from(secretHex ,'hex'))
                                    .update(signingKey)
                                    .digest();
     const actualSignature = Buffer.from(keyparts[2] ,'base64url');
     if(actualSignature.length !== signature.length) return 'BAD reason=bad_signature';
     return timingSafeEqual(actualSignature, signature) ? `OK kid=${keyKid}` : "BAD reason=bad_signature"
                                    

}

export function lint(token) {
  const parts = token.split(".");

  if (parts.length !== 3) {
    return "bad_token";
  }

  let header;
  let payload;

  try {
    header = JSON.parse(b64u_decode(parts[0]));
    payload = JSON.parse(b64u_decode(parts[1]));
  } catch {
    return "bad_token";
  }

  const issues = [];

  if (typeof header.alg === "string" && header.alg.toLowerCase() === "none") {
    issues.push("alg_none");
  }

  if (!Object.hasOwn(payload, "exp")) {
    issues.push("no_expiration");
  }

  if (
    Object.hasOwn(payload, "exp") &&
    Object.hasOwn(payload, "iat") &&
    payload.exp - payload.iat > 86400
  ) {
    issues.push("long_lived");
  }

  if (Object.hasOwn(payload, "password") || Object.hasOwn(payload, "ssn")) {
    issues.push("pii_in_payload");
  }

  return issues.length === 0 ? "OK" : issues.join(",");
}