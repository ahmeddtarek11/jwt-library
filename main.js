import { readFileSync } from 'node:fs';
import {b64u_encode , b64u_decode , encode_header_and_payload} from "./src/base64url_converter.js"
import {sign , verify}  from "./src/security.js"

function execute(command, value) {
  switch (command.toUpperCase()) {
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

    case "VERIFY":{
      const separatorIndex = value.indexOf("|");
      if (separatorIndex === -1) throw new Error("Invalid VERIFY input");
      const token = value.slice(0, separatorIndex);
      const secretHex = value.slice(separatorIndex + 1);
     return verify(token, secretHex);
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
  const Commands = ["ENCODE", "DECODE", "SIGN", "VERIFY"];
  for (const line of input.split(/\r?\n/)) {
    if (!line) continue;

    const spaceIndex = line.indexOf(" ");
    const command = spaceIndex === -1 ? line : line.slice(0, spaceIndex);
    const value = spaceIndex === -1 ? "" : line.slice(spaceIndex + 1);
    const commandName = command.toUpperCase();



    if(Commands.includes(commandName)){
    console.log(execute(command, value));
    }
    else if(line.includes('|')){
      console.log(encode_header_and_payload(line));
    }
    else {
    throw new Error(`Unknown input: ${line}`);
  }
    
  }
}
