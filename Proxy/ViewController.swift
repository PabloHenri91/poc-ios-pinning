//
//  ViewController.swift
//  Proxy
//
//  Created by John Lenon Reis on 10/03/21.
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
        var secresult = SecTrustResultType.invalid
        let status = SecTrustEvaluate(serverTrust, &secresult)

        guard status == errSecSuccess else { return false }

        // For each certificate in the valid trust:
        for index in 0..<SecTrustGetCertificateCount(serverTrust) {
            // Get the public key data for the certificate at the current index of the loop.
            guard let certificate = SecTrustGetCertificateAtIndex(serverTrust, index),
                let publicKey = SecCertificateCopyPublicKey(certificate),
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

struct HttpConnectorResult {

    var statusCode: Int = 0
    var receivedData: NSData = .init()
    var message: NSString = ""
    var wasFailedBecauseTimeOut: Bool = false
    
    func success() -> Bool {
        return statusCode >= 200 && statusCode < 300
    }

    func receivedDataAsUTF8String() -> String? {
        return String(data: receivedData as Data, encoding: .utf8)
    }

    func isClientError() -> Bool {
        return statusCode >= 400 && statusCode < 500
    }
    
    func printData() {
        print("statusCode", statusCode)
        print("receivedData", receivedData)
        print("message", message)
        print("wasFailedBecauseTimeOut", wasFailedBecauseTimeOut)
        print("success", success())
        print("receivedDataAsUTF8String", receivedDataAsUTF8String() as Any)
        print("isClientError", isClientError())
    }
}

class HttpConnectionService {
    func createConnector() -> HttpConnector {
        return HttpConnector()
    }
    
    func getContentLengthFromResponse(response: HTTPURLResponse) -> NSNumber? {
        var result: NSNumber? = nil
        
        for key in response.allHeaderFields.keys {
            if (key as! NSString).lowercased == "content-length" {
                result = NSNumber(value: (response.allHeaderFields[key] as! NSString).intValue)
            }
        }
        
        return result
    }
    
    func isReceivedDataValid(_ data: NSData, response: HTTPURLResponse) -> Bool {
        let expectedContentLength = self.getContentLengthFromResponse(response: response)
        let containsExpectedContentLength = expectedContentLength != nil
        if containsExpectedContentLength {
            return data.length == expectedContentLength!.intValue;
        }
        
        return true
    }
    
    func createResultFromResponse(response: HTTPURLResponse, receivedData:NSData, error:NSError?) -> HttpConnectorResult {
        var result = HttpConnectorResult()
        
        result.receivedData = receivedData
        result.statusCode = response.statusCode
        let success = error == nil && result.success() && self.isReceivedDataValid(result.receivedData, response:response)
        if (!success)
        {
            let isStatusCodeSuccess = result.success
            
            if isStatusCodeSuccess() {
                result.statusCode = 0;
            }
            
            if error != nil {
                result.message = (error?.localizedDescription ?? "") as NSString
                result.wasFailedBecauseTimeOut = error?.code == NSURLErrorTimedOut;
            }
            else {
                result.message = HTTPURLResponse.localizedString(forStatusCode: response.statusCode) as NSString
            }
        }
        
        return result;
    }
}

class HttpConnector: NSObject, URLSessionDelegate, URLSessionDataDelegate {
    
    var urlSession: URLSession!
    var httpConnectorService: HttpConnectionService!
    
    override init() {
        super.init()
        self.urlSession = URLSession(configuration: .default, delegate: self, delegateQueue: nil)
        self.httpConnectorService = HttpConnectionService()
    }
    
    func connect(to url: URL) {
        
        self.urlSession.dataTask(with: url) { data, response, error in
            
            print(response)
            
            if let data = data {
                print("Data", String(data: data, encoding: .utf8))
            }
            
            print("Error: ", error?.localizedDescription, error)
        }.resume()
        
        //self.urlSession.dataTask(with: url).resume()
    }
    
    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        print("didCompleteWithError")
        let result = self.httpConnectorService.createResultFromResponse(response: .init(), receivedData: .init(), error: error as NSError?)
        result.printData()
    }
    
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        print("didReceiveData")
        let result = self.httpConnectorService.createResultFromResponse(response: .init(), receivedData: data as NSData, error: nil)
        result.printData()
    }
    
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse, completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        print("didReceiveResponse")
        let result = self.httpConnectorService.createResultFromResponse(response: response as! HTTPURLResponse, receivedData: .init(), error: nil)
        result.printData()
    }
    
    func urlSession(_ session: URLSession, task: URLSessionTask, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard let trust: SecTrust = challenge.protectionSpace.serverTrust else {
            return
        }
        
        let pinner = PublicKeyPinner(hashes: [
            "TsshcWS7+i8HqvxNXGlWB7MciqndwD5+pLaEf3v1c7o=",
            "klO23nT2ehFDXCfx3eHTDRESMz3asj1muO+4aIdjiuY="
        ])
        
        if pinner.validate(serverTrust: trust, domain: nil) {
            print("Valid Pin!")
            completionHandler(.useCredential, URLCredential.init(trust: trust) )
        } else {
            print("Invalid Pin!")
            /// busca novos pins
            /// se der invalido novamente é erro
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}

class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.
    }

    @IBAction func testProxy(_ sender: Any) {
        let url = URL(string: "https://api.umov.me/CenterWeb/api/2159e486a03a268d015caa72b19af0cc10d10/activity.xml?id=1035444")!
        HttpConnector().connect(to: url)
    }
}
