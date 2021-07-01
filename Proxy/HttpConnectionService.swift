//
//  HttpConnectionService.swift
//  Proxy
//
//  Created by Pablo Bertaco on 04/05/21.
//

import UIKit

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
