W3C XML Encryption implementation for node.js (http://www.w3.org/TR/xmlenc-core/)

## Usage

    npm install xml-encryption

### encrypt

    var xmlenc = require('xmlenc');
    
    var options = {
      rsa_pub: fs.readFileSync(__dirname + '/your_rsa.pub'),
      pem: fs.readFileSync(__dirname + '/your_public_cert.pem'),
      encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#aes-256-cbc',
      keyEncryptionAlgorighm: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p'
    };

    xmlenc.encrypt('content to encrypt', options, function(err, result) { 
        console.log(result);
    }

    // result
    
    <xenc:EncryptedData Type="http://www.w3.org/2001/04/xmlenc#Element" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
      <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes-256-cbc" />
        <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
          <e:EncryptedKey xmlns:e="http://www.w3.org/2001/04/xmlenc#">
            <e:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p">
              <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" />
            </e:EncryptionMethod>
            <KeyInfo>
              <X509Data><X509Certificate>MIIEDzCCAveg... base64 cert... q3uaLvlAUo=</X509Certificate></X509Data>
            </KeyInfo>
            <e:CipherData>
              <e:CipherValue>sGH0hhzkjmLWYYY0gyQMampDM... encrypted symmetric key ...gewHMbtZafk1MHh9A==</e:CipherValue>
            </e:CipherData>
          </e:EncryptedKey>
        </KeyInfo>
        <xenc:CipherData>
            <xenc:CipherValue>V3Vb1vDl055Lp92zvK..... encrypted content.... kNzP6xTu7/L9EMAeU</xenc:CipherValue>
        </xenc:CipherData>
    </xenc:EncryptedData>

### decrypt


    var options = {
        key: fs.readFileSync(__dirname + '/your_private_key.key'),
    };

    xmlenc.decrypt('<xenc:EncryptedData ..... </xenc:EncryptedData>', options, function(err, result) { 
        console.log(result);
    }

    // result

    decrypted content

## Supported algorithms

Currently the library supports:

* EncryptedKey to transport symmetric key using http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p
* EncryptedData using http://www.w3.org/2001/04/xmlenc#aes-256-cbc

However, you can fork and implement your own algorithm. The code supports adding more algorithms easily
