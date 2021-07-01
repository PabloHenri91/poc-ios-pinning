//
//  HttpConnectorResult.swift
//  Proxy
//
//  Created by Pablo Bertaco on 04/05/21.
//

import UIKit

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
