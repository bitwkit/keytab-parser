
const ENCODING_TYPES = {
    0: "reserved",
    1: "des-cbc-crc",
    2: "des-cbc-md4",
    3: "des-cbc-md5",
    4: "Reserved",
    5: "des3-cbc-md5",
    6: "Reserved",
    7: "des3-cbc-sha1",
    8: "Unassigned",
    9: "dsaWithSHA1-CmsOID",
    10: "md5WithRSAEncryption-CmsOID",
    11: "sha1WithRSAEncryption-CmsOID",
    12: "rc2CBC-EnvOID",
    13: "rsaEncryption-EnvOID",
    14: "rsaES-OAEP-ENV-OID",
    15: "des-ede3-cbc-Env-OID",
    16: "des3-cbc-sha1-kd",
    17: "aes128-cts-hmac-sha1-96",
    18: "aes256-cts-hmac-sha1-96",
    19: "aes128-cts-hmac-sha256-128",
    20: "aes256-cts-hmac-sha384-192",
    // 21-22: Unassigned
    23: "rc4-hmac",
    24: "rc4-hmac-exp",
    25: "camellia128-cts-cmac",
    26: "camellia256-cts-cmac",
    // 27-64: Unassigned
    65: "subkey-keymaterial"
};

function readKeytab(kt, pos = 0) {
    const v2 = kt.readUInt8(1) == 2;
    
    // version 2 uses big endian while v1 uses little endian
    kt.readInt16 = v2 ? kt.readInt16BE : kt.readInt16LE;
    kt.readInt32 = v2 ? kt.readInt32BE : kt.readInt32LE;
    
    kt.readUInt16 = v2 ? kt.readUInt16BE : kt.readUInt16LE;
    kt.readUInt32 = v2 ? kt.readUInt32BE : kt.readUInt32LE;
    
    // wrap standand buffer read functions to increment read position with respect to number of bytes read
    function i8() {
        const res = kt.readInt8(pos);
        pos += 1;
        return res;
    };
    
    function i16() {
        const res = kt.readInt16(pos);
        pos += 2;
        return res;
    };
    
    function i32() {
        const res = kt.readInt32(pos);
        pos += 4;
        return res;
    };
    
    function ui8() {
        const res = kt.readUInt8(pos);
        pos += 1;
        return res;
    };
    
    function ui16() {
        const res = kt.readUInt16(pos);
        pos += 2;
        return res;
    };
    
    function ui32() {
        const res = kt.readUInt32(pos);
        pos += 4;
        return res;
    };

    function readVersion() {
        return {
            major: ui8(),
            minor: ui8()
        }
    };
    
    // each function below represents a data structure as described in MIT Kerberos documentation
    function readEntries() {
        const res = [];
        while (pos < kt.length) res.push(readEntry(i32()));
        return res;
    };
    
    function readEntry(size) {
        if (size == 0) {
            return {};
        } else if (size < 0) {
            for (let i = size; i < 0; i++) i8();
            return {};
        };
        
        const startPos = pos;
        const numComponents = ui16() - (!v2 ? 1 : 0);
        const res = {
            numComponents,
            realm: readCountedOctetString(ui16()),
            components: [...Array(numComponents)].map( () => readCountedOctetString(ui16()) ),
            nameType: v2 ? ui32() : undefined,
            timestamp: ui32(),
            vno8: ui8(),
            key: readKeyblock(),
            vno: (pos - startPos - size >= 0) ? [...Array(pos - startPos - size)].map( () => ui8() ) : undefined
        };
        return res;
    };
    
    function readCountedOctetString(length) {
        return [...Array(length)].map( () => ui8() );
    };
    
    function readKeyblock() {
        return {
            type: ui16(),
            value: readCountedOctetString(ui16())
        };
    };

    return {
        version: readVersion(),
        entries: readEntries()
    };
};

function getKey(ktObj) {
    // return key for specified realm, spn and coding type
}

exports.readKeytab = readKeytab;
exports.ENCODING_TYPES = ENCODING_TYPES;
