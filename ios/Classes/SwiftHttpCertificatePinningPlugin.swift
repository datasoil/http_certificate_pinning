import Flutter
import UIKit
import CryptoSwift
import Alamofire

public class SwiftHttpCertificatePinningPlugin: NSObject, FlutterPlugin {

    let session = Session.default;

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

        var timeout = 60
        if let timeoutArg = args["timeout"] as? Int {
            timeout = timeoutArg
        }
        
        let configuration = URLSessionConfiguration.default
        configuration.timeoutIntervalForRequest = TimeInterval(timeout)
        
        let evaluator = CustomServerTrustManager(fingerprints: fingerprints, type: type, flutterResult: flutterResult)
        let session = Session(
            configuration: configuration,
            serverTrustManager: ServerTrustManager(evaluators: [
                urlString.components(separatedBy: "/")[2]: evaluator
            ])
        )
        
        var resultDispatched = false
        
        session.request(urlString, method: .get, parameters: headers)
            .validate()
            .responseJSON { response in
                switch response.result {
                case .success:
                    break
                case .failure(let error):
                    if (!resultDispatched) {
                        flutterResult(
                            FlutterError(
                                code: "URL Format",
                                message: error.localizedDescription,
                                details: nil
                            )
                        )
                    }
                    break
                }
                
                // To retain
                let _ = session
        }
    }
}

class CustomServerTrustManager: ServerTrustEvaluating {
    private let fingerprints: Array<String>
    private let type: String
    private let flutterResult: FlutterResult
    
    init(fingerprints: Array<String>, type: String, flutterResult: @escaping FlutterResult) {
        self.fingerprints = fingerprints
        self.type = type
        self.flutterResult = flutterResult
    }
    
    func evaluate(_ trust: SecTrust, forHost host: String) throws {
        guard let certificate = SecTrustGetCertificateAtIndex(trust, 0) else {
            flutterResult(
                FlutterError(
                    code: "ERROR CERT",
                    message: "Invalid Certificate",
                    details: nil
                )
            )
            throw AFError.serverTrustEvaluationFailed(reason: .noRequiredEvaluator(host: host))
        }
        
        // Set SSL policies for domain name check
        let policies: [SecPolicy] = [SecPolicyCreateSSL(true, (host as CFString))]
        SecTrustSetPolicies(trust, policies as CFTypeRef)
        
        // Evaluate server certificate
        var result: SecTrustResultType = .invalid
        SecTrustEvaluate(trust, &result)
        let isServerTrusted: Bool = (result == .unspecified || result == .proceed)
        
        let serverCertData = SecCertificateCopyData(certificate) as Data
        var serverCertSha = serverCertData.sha256().toHexString()
        
        if(type == "SHA1"){
            serverCertSha = serverCertData.sha1().toHexString()
        }
        
        let fp = fingerprints.compactMap { (val) -> String? in
            val.replacingOccurrences(of: " ", with: "")
        }
        
        let isSecure = fp.contains(where: { (value) -> Bool in
            value.caseInsensitiveCompare(serverCertSha) == .orderedSame
        })
        
        if isServerTrusted && isSecure {
            flutterResult("CONNECTION_SECURE")
        } else {
            flutterResult(
                FlutterError(
                    code: "CONNECTION_NOT_SECURE",
                    message: nil,
                    details: nil
                )
            )
            throw AFError.serverTrustEvaluationFailed(reason: .noRequiredEvaluator(host: host))
        }
    }
}
