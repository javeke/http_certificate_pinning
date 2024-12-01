import Flutter
import UIKit
import CryptoSwift
import Alamofire

class ResultDispatchedWrapper {
    var value: Bool
    
    init(value: Bool) {
        self.value = value
    }
}

class SHA256TrustEvaluator: ServerTrustEvaluating {
    private let validFingerprints: Array<String>?
    private let expectedHost: String
    private let flutterResult: FlutterResult
    private let type: String
    private var resultDispatched: ResultDispatchedWrapper
    

    init(validFingerprints: [String], expectedHost: String, flutterResult: @escaping FlutterResult, type: String, resultDispatched: ResultDispatchedWrapper) {
        self.validFingerprints = validFingerprints
        self.expectedHost = expectedHost
        self.flutterResult = flutterResult
        self.type = type
        self.resultDispatched = resultDispatched
    }

    func evaluate(_ trust: SecTrust, forHost host: String) throws {
        guard host == expectedHost else {
            flutterResult(
                FlutterError(
                    code: "ERROR CERT",
                    message: "Invalid Host",
                    details: nil
                )
            )
            throw AFError.serverTrustEvaluationFailed(reason: .trustEvaluationFailed(error: nil))
        }
        
        guard let serverCertificate = SecTrustGetCertificateAtIndex(trust, 0) else {
            flutterResult(
                FlutterError(
                    code: "ERROR CERT",
                    message: "Invalid Certificate",
                    details: nil
                )
            )
            throw AFError.serverTrustEvaluationFailed(reason: .noCertificatesFound)
        }
        
        let serverCertificateData = SecCertificateCopyData(serverCertificate) as Data
        
        
        var serverFingerprint = sha256(data: serverCertificateData)
        if(type == "SHA1"){
            serverFingerprint = serverCertificateData.sha1().toHexString()
        }
        
        
        var result: SecTrustResultType = .invalid
        SecTrustEvaluate(trust, &result)
        let isServerTrusted: Bool = (result == .unspecified || result == .proceed)

        var isSecure = false
        if var fp = self.validFingerprints {
            fp = fp.compactMap { (val) -> String? in
                val.replacingOccurrences(of: " ", with: "")
        }

            isSecure = fp.contains(where: { (value) -> Bool in
                value.caseInsensitiveCompare(serverFingerprint) == .orderedSame
            })
        }
        
        if isServerTrusted && isSecure {
            flutterResult("CONNECTION_SECURE")
            resultDispatched.value = true
        } else {
            flutterResult(
                FlutterError(
                    code: "CONNECTION_NOT_SECURE",
                    message: nil,
                    details: nil
                )
            )
            resultDispatched.value = true
        }
    }

    private func sha256(data: Data) -> String {
        return data.sha256().toHexString()
    }
}


public class SwiftHttpCertificatePinningPlugin: NSObject, FlutterPlugin {
    var fingerprints: Array<String>?
    var flutterResult: FlutterResult?

    public static func register(with registrar: FlutterPluginRegistrar) {
        let channel = FlutterMethodChannel(name: "http_certificate_pinning", binaryMessenger: registrar.messenger())
        let instance = SwiftHttpCertificatePinningPlugin()
        registrar.addMethodCallDelegate(instance, channel: channel)
    }

    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        switch (call.method) {
            case "check":
                if let _args = call.arguments as? Dictionary<String, AnyObject> {
                    self.check(call: call, args: _args, flutterResult: result)
                } else {
                    result(
                        FlutterError(
                            code: "Invalid Arguments",
                            message: "Please specify arguments",
                            details: nil)
                    )
                }
                break
        default:
            result(FlutterMethodNotImplemented)
        }
    }
    
    func getDomain(from urlString: String) -> String? {
        if let url = URL(string: urlString) {
            return url.host
        }
        return nil
    }

    public func check(
        call: FlutterMethodCall,
        args: Dictionary<String, AnyObject>,
        flutterResult: @escaping FlutterResult
    ){
        guard let urlString = args["url"] as? String,
              let headers = args["headers"] as? Dictionary<String, String>,
              let fingerprints = args["fingerprints"] as? Array<String>,
              let type = args["type"] as? String
        else {
            flutterResult(
                FlutterError(
                    code: "Params incorrect",
                    message: "Les params sont incorrect",
                    details: nil
                )
            )
            return
        }

        self.fingerprints = fingerprints

        var timeout = 60
        if let timeoutArg = args["timeout"] as? Int {
            timeout = timeoutArg
        }
        
        let resultDispatched = ResultDispatchedWrapper(value: false)
        
        let host : String = getDomain(from: urlString) ?? ""
        
        let configuration = URLSessionConfiguration.default
        
        // Evaluate certificates each time
        //configuration.httpShouldUsePipelining = false
        //configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        
        let manager = Session(
            configuration: configuration,
            serverTrustManager: ServerTrustManager(evaluators: [host:SHA256TrustEvaluator(validFingerprints: fingerprints, expectedHost: host, flutterResult: flutterResult, type: type, resultDispatched: resultDispatched)])
        )
        
        manager.session.configuration.timeoutIntervalForRequest = TimeInterval(timeout)
        
        manager.request(urlString, method: .get, parameters: headers).validate().response() { response in
            switch response.result {
                case .success:
                    break
            case .failure(let error):
                if (!resultDispatched.value) {
                    flutterResult(
                        FlutterError(
                            code: "URL Format",
                            message: error.localizedDescription,
                            details: error.failureReason
                        )
                    )
                    resultDispatched.value = true
               }
                   
                break
            }
            
            //if (!resultDispatched.value) {
            //    flutterResult("CONNECTION STATUS UNKNOWN")
            //}
            
            // To retain
            let _ = manager
        }
    }
}
