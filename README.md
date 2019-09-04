# keytab-parser
A simple parser for Kerberos keytab files based on MIT Kerberos documentation.

## purpose
To extract Kerberos cryptographic keys on server side to decrypt SPNEGO Kerberos tickets coming from clients.

## usage
Parsing is done with a single function **readKeytab(kt: Buffer, pos?: number = 0)**
- *kt* - is a Buffer object with contents of a keytab file
- *pos* - starting point offset in octets (optional and most likely useless)

### example
```javascript
const {readKeytab, ENCODING_TYPES: encTypes} = require('keytab-parser');
const kt = readFileSync(keytabFilename);
const keytab = readKeytab(kt);

// print out the contents
for (const entry of keytab.entries) {
    const components = entry.components.reduce((prev, curr) => prev.concat(curr), [] );
    console.log('realm', String.fromCharCode(...entry.realm), String.fromCharCode(...components), 'keytype', encTypes[entry.key.type], 'key', entry.key.value );
}
```
