//
//  PublicKeyPinner.swift
//  Proxy
//
//  Created by Pablo Bertaco on 04/05/21.
//

import UIKit
import CommonCrypto
import CryptoKit

final class PublicKeyPinner {
    /// Stored public key hashes
    private let hashes: [String]

    public init(hashes: [String]) {
        self.hashes = hashes
    }

    /// ASN1 header for our public key to re-create the subject public key info
    private let rsa2048Asn1Header: [UInt8] = [
        0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
        0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00
    ]

    /// Validates an object used to evaluate trust's certificate by comparing their's public key hashes to the known, trused key hashes stored in the app
    /// Configuration.
    /// - Parameter serverTrust: The object used to evaluate trust.
    public func validate(serverTrust: SecTrust, domain: String?) -> Bool {
        // Set SSL policies for domain name check, if needed
        if let domain = domain {
            let policies = NSMutableArray()
            policies.add(SecPolicyCreateSSL(true, domain as CFString))
            SecTrustSetPolicies(serverTrust, policies)
        }

        // Check if the trust is valid
        var error: CFError? = nil
        let trusted = SecTrustEvaluateWithError(serverTrust, &error)

        guard trusted else { return false }

        // For each certificate in the valid trust:
        for index in 0..<SecTrustGetCertificateCount(serverTrust) {
            // Get the public key data for the certificate at the current index of the loop.
            guard let certificate = SecTrustGetCertificateAtIndex(serverTrust, index),
                  let publicKey = SecCertificateCopyKey(certificate),
                let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, nil) else {
                    return false
            }

            // Hash the key, and check it's validity.
            let keyHash = hash(data: (publicKeyData as NSData) as Data)
            if hashes.contains(keyHash) {
                // Success! This is our server!
                return true
            }
        }

        // If none of the calculated hashes match any of our stored hashes, the connection we tried to establish is untrusted.
        return false
    }

    /// Creates a hash from the received data using the `sha256` algorithm.
    /// `Returns` the `base64` encoded representation of the hash.
    ///
    /// To replicate the output of the `openssl dgst -sha256` command, an array of specific bytes need to be appended to
    /// the beginning of the data to be hashed.
    /// - Parameter data: The data to be hashed.
    private func hash(data: Data) -> String {
        // Add the missing ASN1 header for public keys to re-create the subject public key info
        var keyWithHeader = Data(rsa2048Asn1Header)
        keyWithHeader.append(data)

        // Using CryptoKit
        if #available(iOS 13, *) {
            return Data(SHA256.hash(data: keyWithHeader)).base64EncodedString()
        } else {
            // Using CommonCrypto's CC_SHA256 method
            var hash = [UInt8](repeating: 0,  count: Int(CC_SHA256_DIGEST_LENGTH))
            _ = keyWithHeader.withUnsafeBytes {
                CC_SHA256($0.baseAddress!, CC_LONG(keyWithHeader.count), &hash)
            }
            return Data(hash).base64EncodedString()
        }
    }
}
