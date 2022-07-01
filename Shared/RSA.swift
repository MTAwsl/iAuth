//
//  RSA.swift
//  SteamAuth
//
//  Created by Dominic Socular on 2022/6/29.
//

import Foundation
import BigInt

class RSA{
    static func encrypt(string: String, mod: String, exp: String) -> String
    {
        let secret = pkcs1pad2(data: string.data(using: .utf8)!, keySize: mod.count / 2)!
        return secret.power(BigUInt(exp, radix: 16)!, modulus: BigUInt(mod, radix: 16)!).serialize().base64EncodedString()
    }
    
    static func pkcs1pad2(data: Data, keySize: Int) -> BigUInt?{
        if (keySize < data.count + 11){
            return nil;
        }
        var rndData: [UInt8] = [UInt8](repeating: 0, count: keySize - 3 - data.count)
        let status = SecRandomCopyBytes(kSecRandomDefault, rndData.count, &rndData)
        for i in 0..<rndData.count{
            if rndData[i] == 0{
                rndData[i] = UInt8(i+1)
            }
        }
        guard status == errSecSuccess else{
            return nil
        }
        
        return BigUInt(Data([0x00, 0x02]) + Data(rndData) + Data([0x00]) + data)
    }
}

class RSA2{
    static func rsaPublicKeyder(mod: String, exp: String) -> String{
        
        func prepadSigned(hexStr: String) -> String? {
            guard let msb = hexStr.first else {
                return nil
            }
            if (
                (msb>="8" && msb<="9") ||
                (msb>="a" && msb<="f") ||
                (msb>="A"&&msb<="F")) {
                return "00"+hexStr;
            } else {
                return hexStr;
            }
        }
        
        func toHex(number: Int) -> String{
            let nstr = String(format:"%2X", number).trimmingCharacters(in: .whitespaces)
            if (nstr.count%2==0) {
                return nstr
            }
            return "0"+nstr
        }
        
        // encode ASN.1 DER length field
        // if <=127, short form
        // if >=128, long form
        func encodeLengthHex(n: Int) -> String {
            if (n<=127) {
                return toHex(number: n)
            }
            else {
                let n_hex = toHex(number: n)
                return toHex(number: 128 + n_hex.count/2)+n_hex
            }
        }
        
        let modulus_hex = prepadSigned(hexStr: mod)!
        let exponent_hex = prepadSigned(hexStr: exp)!
        
        let modlen = modulus_hex.count/2
        let explen = exponent_hex.count/2
        
        let encoded_modlen = encodeLengthHex(n: modlen)
        let encoded_explen = encodeLengthHex(n: explen)
        let encoded_pubkey = "30" +
        encodeLengthHex(n:
                            modlen +
                        explen +
                        encoded_modlen.count/2 +
                        encoded_explen.count/2 + 2
        ) +
        "02" + encoded_modlen + modulus_hex +
        "02" + encoded_explen + exponent_hex;
        
        let seq2 =
        "300d06092a864886f70d010101050003" + encodeLengthHex(n:encoded_pubkey.count/2 + 1) +
        "00" + encoded_pubkey;
        
        let der_hex = "30" + encodeLengthHex(n:seq2.count/2) + seq2;
        return der_hex.hexData().base64EncodedString()
    }
    
    static func encrypt(string: String, mod: String, exp: String) -> String? {
        
        let keyString = self.rsaPublicKeyder(mod: mod, exp: exp)
        guard let data = Data(base64Encoded: keyString) else { return nil }
        
        var attributes: CFDictionary {
            return [kSecAttrKeyType         : kSecAttrKeyTypeRSA,
                    kSecAttrKeyClass        : kSecAttrKeyClassPublic,
                    kSecAttrKeySizeInBits   : 2048,
                    kSecReturnPersistentRef : kCFBooleanTrue!] as CFDictionary
        }
        
        var error: Unmanaged<CFError>? = nil
        guard let secKey = SecKeyCreateWithData(data as CFData, attributes, &error) else {
            print(error.debugDescription)
            return nil
        }
        guard let result = SecKeyCreateEncryptedData(secKey, SecKeyAlgorithm.rsaEncryptionPKCS1, string.data(using: .utf8)! as CFData, &error) else{
            print(error.debugDescription)
            return nil
        }
        return (result as Data).base64EncodedString()
    }
}

extension String{
    func hexData() -> Data{
        var result = Data()
        for i in 0..<self.count/2{
            let start = self.index(startIndex, offsetBy: i*2)
            let end = self.index(startIndex, offsetBy: i*2+1)
            result.append(UInt8(self[start...end], radix:16)!)
        }
        return result
    }
}
