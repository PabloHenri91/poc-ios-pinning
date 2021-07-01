//
//  HttpConnector.swift
//  Proxy
//
//  Created by Pablo Bertaco on 04/05/21.
//

import UIKit

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
