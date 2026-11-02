import { readFileSync } from 'node:fs';
import {b64u_encode , b64u_decode , encode_header_and_payload} from "./src/base64url_converter.js"
import { sign, verify, verifyAlg, verifyRs256, validateClaims ,verifyWithKeyStore } from "./src/security.js"

let registeredKey = null;
let registeredKeyKind = null;
let now = null;
let leeway = null;
let expectedIss =null;
let expectedAud = null;
let keystore = new Map(); 
let keyStoreMode = false;

function execute(command, value) {
  switch (command.toUpperCase()) {
    case "KEY": {
    
      const [identifier , secretHex] = value.trim().split(/\s+/);
      if(identifier === 'oct' || identifier === 'pub'){
        registeredKeyKind = identifier;
        registeredKey = secretHex;
      }

      else{
        keyStoreMode = true;
        keystore.set(identifier,secretHex);
      }
      return 'OK';
      
    }
    case "REVOKE":{
      const kid = value.trim();
      if(!kid ||  /\s/.test(kid))throw new Error("invalid input");
      keystore.delete(kid); 
      return 'OK';
      
    }
    case "NOW":{
        if(value === null)throw new Error("Invalid KEY input"); 
        now = Number(value);
        return null;
        
    }
    case"EXPECT_AUD":{
      if(value === null)throw new Error("Invalid KEY input"); 
        expectedAud = value;
        return null;

    }
    case "EXPECT_ISS":{
      if(value === null)throw new Error("Invalid KEY input"); 
        expectedIss = value;
        return null;
        
    }
    case "LEEWAY":{
      if(value === null)throw new Error("Invalid KEY input"); 
        leeway = Number(value);
        return null;
        
    }
    case "ENCODE":
      return b64u_encode(value);

    case "DECODE":
      return b64u_decode(value);

    case "SIGN":{
      const parts = value.split("|");
      if (parts.length !== 3) throw new Error("Invalid SIGN input");

      const [header, payload, secretHex] = parts;
      return sign(header, payload, secretHex); 
    }

      case "VALIDATE":{
        const claims = JSON.parse(value);
        return validateClaims(now , expectedIss ,expectedAud ,leeway ,claims);
        
      }

    case "VERIFY": {
      const separatorIndex = value.indexOf("|");

      if (separatorIndex !== -1) {
        const token = value.slice(0, separatorIndex);
        const key = value.slice(separatorIndex + 1);
        return verifyToken(token, key);
      }
     
      if(keyStoreMode){
        return verifyWithKeyStore(value,keystore);
      }

      if (registeredKey === null || registeredKeyKind === null) {
        return "REJECTED bad_token";
      }
      

      return verifyAlg(value, registeredKey, registeredKeyKind);
    }

    default:
      throw new Error(`Unknown command: ${command}`);
  }
}


const argumentsList = process.argv.slice(2);

if (argumentsList.length > 0) {
  const [command, ...valueParts] = argumentsList;
  console.log(execute(command, valueParts.join(" ")));
} 


else {
  const input = readFileSync(0, "utf8");
  const Commands = 
  ["KEY", "ENCODE", "DECODE", "SIGN", "VERIFY", 
  "VALIDATE" ,"EXPECT_ISS" ,"NOW" ,"EXPECT_AUD" ,"LEEWAY"
    ,"REVOKE"
];
  for (const line of input.split(/\r?\n/)) {
    if (!line) continue;

    const spaceIndex = line.indexOf(" ");
    const command = spaceIndex === -1 ? line : line.slice(0, spaceIndex);
    const value = spaceIndex === -1 ? "" : line.slice(spaceIndex + 1);
    const commandName = command.toUpperCase();



    if(Commands.includes(commandName)){
    const result = execute(command, value);
    if(result !== null && result !== undefined) console.log(result);
    }
    else if(line.includes('|')){
      console.log(encode_header_and_payload(line));
    }
    else {
    throw new Error(`Unknown input: ${line}`);
  }
    
  }
}



function verifyToken(token, key) {
  const headerSegment = token.split(".")[0];

  try {
    const header = JSON.parse(b64u_decode(headerSegment));

    if (header.alg === "RS256") {
      return verifyRs256(token, key);
    }

    return verify(token, key);
  } catch {
    return "BAD";
  }
}
