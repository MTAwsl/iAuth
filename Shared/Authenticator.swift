//
//  Authenticator.swift
//  SteamAuth
//
//  Created by Dominic Socular on 2022/6/19.
//

import Foundation
import CryptoKit
import SwiftUI

let COMMUNITY_BASE_URL: URL = URL(string: "https://steamcommunity.com")!

enum ErrorType: Error{
    case ERR_SUCCESS
    case ERR_NETWORK_TIMEOUT
    case ERR_INVALID_RESPONSE
    case ERR_INVALID_JSON
}

class SteamTimeSync{
    static let shared = SteamTimeSync()
    let SYNC_TIME_URL = "https://api.steampowered.com:443/ITwoFactorService/QueryTime/v0001"
    var ServerTimeDiff: Int64 = 0
    var timesyncstat: Bool = false // Is timesyncing in progress?
    var lastSyncTime: Int64 = 0
    var lastError: ErrorType = ErrorType.ERR_SUCCESS
    var lastErrorTime:Int64 = 0
    
    private struct SERVER_TIME_RESP: Decodable {
        let Time: Int64
        
        // MARK: - Codable
        private enum RootCodingKeys: String, CodingKey {
            
            case response = "response"
            
            enum NestedCodingKeys: String, CodingKey {
                case server_time
            }
        }
        
        public init(from decoder: Decoder) throws {
            let rootContainer = try decoder.container(keyedBy: RootCodingKeys.self)
            let userDataContainer = try rootContainer.nestedContainer(keyedBy: RootCodingKeys.NestedCodingKeys.self, forKey: .response)
            
            self.Time = try Int64(userDataContainer.decode(String.self, forKey: .server_time))!
        }
    }
    
    private init(){}
    
    func getServerTime() -> Int64{
       return (Int64(Date().timeIntervalSince1970) + self.ServerTimeDiff)
    }
    
    func SyncTime(forceResync:Bool=false) -> Void{
        let curTime = Int64(Date().timeIntervalSince1970)-1
        self.timesyncstat = true
        if !forceResync && !self.timesyncstat && lastErrorTime >= curTime - 300 && lastSyncTime >= curTime - 900{
            // Do not retry in 5 minutes
            return
        }
        var request = URLRequest(url:URL(string:SYNC_TIME_URL)!)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("application/json", forHTTPHeaderField: "Content_Type")
        let dataTask = URLSession.shared.dataTask(with: request){
            data, resp, err in
            guard
                    let data = data,
                    let response = resp as? HTTPURLResponse,
                    err == nil
            else {
                if (err as? URLError)?.code == .timedOut {
                    print("Error when Syncing Time: Timed out")
                    self.lastError = ErrorType.ERR_NETWORK_TIMEOUT
                    self.lastErrorTime = curTime
                    self.timesyncstat = false;
                    return
                }
                print("Error when Syncing Time: ", err ?? URLError(.badServerResponse))
                self.lastError = ErrorType.ERR_INVALID_RESPONSE
                self.lastErrorTime = curTime
                self.timesyncstat = false;
                return
            }
            guard (200 ... 299) ~= response.statusCode else {
                print("Error when Syncing Time: ")
                print("statusCode should be 2xx, but is \(response.statusCode)")
                print("response = \(response)")
                self.lastError = ErrorType.ERR_INVALID_RESPONSE
                self.lastErrorTime = curTime
                self.timesyncstat = false;
                return
            }
            let decoder = JSONDecoder()
            do{
                let result = try decoder.decode(SERVER_TIME_RESP.self, from: data)
                self.ServerTimeDiff = curTime - result.Time
                self.lastError = ErrorType.ERR_SUCCESS
                self.lastSyncTime = curTime
                self.timesyncstat = false
                print("Time Synced with steam server.")
                return
            }catch(let err){
                print("Error when Syncing Time:")
                print("Decoding Error:", err)
                self.lastError = ErrorType.ERR_INVALID_JSON
                self.lastErrorTime = curTime
                self.timesyncstat = false
                return
            }
        }
        dataTask.resume()
    }
}

class Authenticator {
    var key: Data
    let CODE_DIGIT: [Character] = ["2", "3", "4", "5", "6", "7", "8", "9", "B", "C","D", "F", "G", "H", "J", "K", "M", "N", "P", "Q", "R", "T", "V", "W", "X", "Y"]
    
    init(key: String){
        self.key = Data(base64Encoded: key)!
    }
    
    func UpdateKey(key: String){
        self.key = Data(base64Encoded: key)!
    }
    
    func CalculateCode(forceResync:Bool=false) -> String{
        if !SteamTimeSync.shared.timesyncstat && (forceResync || SteamTimeSync.shared.ServerTimeDiff == 0) {
            SteamTimeSync.shared.SyncTime(forceResync: forceResync)
        }
        var hmac = HMAC<Insecure.SHA1>(key: SymmetricKey(data:self.key))
        let time = SteamTimeSync.shared.getServerTime() / 30
        hmac.update(data: withUnsafeBytes(of: time.bigEndian, {Data($0)}))
        let mac = withUnsafeBytes(of: hmac.finalize(), {Data($0).prefix(20)})
        var codePoint = Int(mac.advanced(by: Int(mac[19] & 0xf)).withUnsafeBytes({(rawPtr :UnsafeRawBufferPointer) in
            return rawPtr.load(as: UInt32.self)
        }).bigEndian)

        var result = String()
        for _ in 0...4{
            result.append(CODE_DIGIT[codePoint % CODE_DIGIT.count])
            codePoint /= CODE_DIGIT.count
        }
        
        return result
    }
}

class SteamClient{
    
    struct Confirmation{
        let Id: String
        let Key: String
        let Offline: Bool
        let isNew: Bool
        let Image: String
        let Details: String
        let Traded: String
        let When: String
    }
    
    struct RSAResponse: Decodable {
        let success: Bool
        let publickey_mod: String
        let publickey_exp: String
        let timestamp: String
        let token_gid: String
    }
    
    let username, password: String
    let sharedSecret, identitySecret: String
    let deviceID: String
    var SteamId: String? = nil
    var OAuthToken: String? = nil
    var MessageId: Int? = nil
    var Session: URLSession = URLSession(configuration: URLSessionConfiguration.default)
    
    private var auth: Authenticator
    private var InvalidLogin: Bool = false
    private var Require2FA: Bool = false
    private var RequireCaptcha: Bool = false
    private var RequiresEmail: Bool = false
    private var CaptchaId : String? = nil
    private var CaptchaUrl: String? = nil
    private var EmailDomain: String? = nil
    private var message: String? = nil
    private var oauth: OAuth? = nil
    
    let _tradeRegex = try! NSRegularExpression(pattern: "\"mobileconf_list_entry\"(.*?)>(.*?)\"mobileconf_list_entry_sep\"",options: [.caseInsensitive])
    let _tradeConfidRegex = try! NSRegularExpression(pattern: "data-confid\\s*=\\s*\"([^\"]+)\"", options: .caseInsensitive)
    let _tradePlayerRegex = try! NSRegularExpression(pattern: "\"mobileconf_list_entry_icon\"(.*?)src=\"([^\"]+)\"", options:.caseInsensitive)
    let _tradeKeyRegex = try! NSRegularExpression(pattern: "data-key\\s*=\\s*\"([^\"]+)\"", options: .caseInsensitive)
    let _tradeDetailsRegex = try! NSRegularExpression(pattern: "\"mobileconf_list_entry_description\".*?<div>([^<]*)</div>[^<]*<div>([^<]*)</div>[^<]*<div>([^<]*)</div>[^<]*</div>", options:.caseInsensitive)
    
    struct OAuth : Decodable
    {
        let steamid: String
        let oauth_token: String
        let wgtoken: String
        let wgtoken_secure: String
    }
    
    struct LoginResponse : Decodable
    {
        let success: Bool
        let login_complete: Bool?
        let oauth: String?
        let captcha_gid: String?
        let captcha_needed: Bool?
        let emailsteamid: String?
        let emailauth_needed: Bool?
        let requires_twofactor: Bool?
        let message: String?
    }
    
    enum LoginResult
    {
        case LoginOkay
        case GeneralFailure
        case BadRSA
        case BadCredentials
        case NeedCaptcha
        case Need2FA
        case NeedEmail
        case TooManyFailedLogins
    }
    
    func isLoggedIn()-> Bool{
        return self.SteamId != nil && self.OAuthToken != nil
    }
    
    func captchaGid() -> String?
    {
        return self.CaptchaId
    }
    
    func getMessage() -> String?{
        return self.message
    }
    
    private func setCookie(key: String, value: String) -> Void{
        if let cookie = HTTPCookie(properties: [
            .domain: ".steamcommunity.com",
            .path: "/",
            .name: key,
            .value: value,
            .secure: "FALSE",
            .discard: "TRUE"
        ]) {
            self.Session.configuration.httpCookieStorage!.setCookie(cookie)
        }
    }
    
    private func initcookies() -> Void{
        if self.Session.configuration.httpCookieStorage == nil {
            self.Session.configuration.httpCookieStorage = HTTPCookieStorage()
        }
        
        // Setting up Cookies
        let initCookies: KeyValuePairs = ["mobileClientVersion": "3067969+%282.1.3%29",
                                          "mobileClient": "android",
                                          "steamid": "",
                                          "steamLogin": "",
                                          "Steam_Language": "english",
                                          "dob": ""
        ]
        for cookie in initCookies{
            setCookie(key: cookie.key, value:cookie.value)
        }
        if var headers = self.Session.configuration.httpAdditionalHeaders{
            headers["User-Agent"] = "Mozilla/5.0 (iPhone; CPU iPhone OS 12_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148"
            headers["Accept"] = "text/javascript, text/html, application/xml, text/xml, */*"
            headers["X-Requested-With"] = "com.valvesoftware.android.steam.community"
        }
        else{
            self.Session.configuration.httpAdditionalHeaders = ["X-Requested-With": "com.valvesoftware.android.steam.community", "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 12_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148", "Accept": "text/javascript, text/html, application/xml, text/xml, */*"]
        }
    }
    
    init(auth: Authenticator, username: String, password: String, identitySecret: String, deviceId: String){
        self.auth = auth
        self.deviceID = deviceId
        self.sharedSecret = auth.key.base64EncodedString()
        self.identitySecret = identitySecret
        self.username = username.replacingOccurrences(of: "[^\u{0000}-\u{007F}]", with: "", options: .regularExpression)
        self.password = password.replacingOccurrences(of: "[^\u{0000}-\u{007F}]", with: "", options: .regularExpression)
        self.initcookies()
    }
    
    init(sharedsec: String, username: String, password: String, identitySecret: String, deviceId: String){
        self.sharedSecret = sharedsec
        self.identitySecret = identitySecret
        self.deviceID = deviceId
        self.auth = Authenticator(key: sharedsec)
        self.username = username.replacingOccurrences(of: "[^\u{0000}-\u{007F}]", with: "", options: .regularExpression)
        self.password = password.replacingOccurrences(of: "[^\u{0000}-\u{007F}]", with: "", options: .regularExpression)
        self.initcookies()
    }
    
    func CreateTimeHash(time: Int64 = SteamTimeSync.shared.getServerTime(), tag: String) -> String{
        let index1 = tag.index(tag.startIndex, offsetBy: 0)
        let index2 = tag.index(tag.startIndex, offsetBy: tag.count > 32 ? 32: tag.count)
        let encData = withUnsafeBytes(of: time.bigEndian, {Data($0)}) + tag[index1..<index2].data(using: .utf8)!
        var hmac = HMAC<Insecure.SHA1>(key: SymmetricKey(data:Data(base64Encoded: self.identitySecret)!))
        hmac.update(data: encData)
        return withUnsafeBytes(of: hmac.finalize(), {Data($0).prefix(20)}).base64EncodedString() // SHA-1 Data length is 20 bytes, must be limited.
    }
    
    func Refresh() async -> Void{
        struct tokenresponse: Decodable{
            let token: String
            let token_secure: String
        }
        
        guard let token = self.oauth?.oauth_token else {return}
        do{
            let (data, response) = try await self.Session.callPost(url: COMMUNITY_BASE_URL.appendingPathComponent("/IMobileAuthService/GetWGToken/v0001"), params: ["access_token": token])
            guard let httpResponse = response as? HTTPURLResponse,
                  httpResponse.statusCode == 200 else {
                throw ErrorType.ERR_INVALID_RESPONSE
            }
            let index1 = data.index(data.startIndex, offsetBy: 12)
            let index2 = data.index(data.endIndex, offsetBy: -1)
            let token_resp: tokenresponse = try JSONDecoder().decode(tokenresponse.self, from: data[index1..<index2])
            setCookie(key: "steamLogin", value: self.oauth!.steamid+"||"+token_resp.token)
            setCookie(key: "steamLoginSecure", value: self.oauth!.steamid+"||"+token_resp.token_secure)
            
        }
        catch(let e){
            print("An error occured when refreshing token: ", e)
        }
    }
    
    func Login(captchaId: String? = nil, captchaText: String? = nil) async -> LoginResult{
        
        do{
            let (_, _) = try await self.Session.data(from: COMMUNITY_BASE_URL.appendingPathComponent("/mobilelogin").appending("oauth_client_id",value:"DE45CD61").appending("oauth_scope", value:"read_profile write_profile read_client write_client"))
        
            var (data, response) = try await self.Session.callPost(url: COMMUNITY_BASE_URL.appendingPathComponent("/login/getrsakey"), params: ["username": username])
            guard let httpResponse = response as? HTTPURLResponse,
                  httpResponse.statusCode == 200 else {
                throw ErrorType.ERR_INVALID_RESPONSE
            }
            let RSAKey = try JSONDecoder().decode(RSAResponse.self, from: data)
            guard RSAKey.success else{
                return LoginResult.BadRSA
            }
            
            let encPwd64 = RSA.encrypt(string: password, mod: RSAKey.publickey_mod, exp: RSAKey.publickey_exp)
            
            let postData = ["password": encPwd64, "username": username, "twofactorcode": self.auth.CalculateCode(), "loginfriendlyname": "#login_emailauth_friendlyname_mobile", "captchagid": captchaId ?? "-1", "captcha_text": captchaText ?? "enter above characters", "rsatimestamp": RSAKey.timestamp, "remember_login": "false", "oauth_client_id": "DE45CD61", "oauth_scope": "read_profile write_profile read_client write_client", "donotache": String(UInt64(Date().timeIntervalSince1970)*1000)]
            (data, response) = try await self.Session.callPost(url: COMMUNITY_BASE_URL.appendingPathComponent("/login/dologin"), params: postData as [String : Any])
            guard let httpResponse = response as? HTTPURLResponse,
                  httpResponse.statusCode == 200 else {
                throw ErrorType.ERR_INVALID_RESPONSE
            }
            
            let jsonString = String(data: data, encoding: .utf8)!.replacingOccurrences(of: "\"captcha_gid\":-1", with: "\"captcha_gid\":\"-1\"")
            
            let loginResponse: LoginResponse = try JSONDecoder().decode(LoginResponse.self, from: jsonString.data(using: .utf8)!)

            if let msg = loginResponse.message {
                self.message = msg
                if(msg.contains("There have been too many login failures")){
                    self.InvalidLogin = true
                    return LoginResult.TooManyFailedLogins;
                }
                
                if(msg.contains("The account name or password that you have entered is incorrect")){
                    self.InvalidLogin = true
                    return LoginResult.BadCredentials;
                }
            }
            
            if let bCap = loginResponse.captcha_needed
            {
                if bCap{
                    self.RequireCaptcha = true;
                    self.CaptchaId = loginResponse.captcha_gid;
                    self.InvalidLogin = true
                    return LoginResult.NeedCaptcha;
                }
            }
            
            if let bEml = loginResponse.emailauth_needed
            {
                if bEml{
                    self.RequiresEmail = true;
                    self.SteamId = loginResponse.emailsteamid;
                    self.InvalidLogin = true
                    return LoginResult.NeedEmail;
                }
            }
            
            if let b2fa = loginResponse.requires_twofactor
            {
                if b2fa && !loginResponse.success {
                    self.Require2FA = true;
                    self.InvalidLogin = true
                    return LoginResult.Need2FA;
                }
            }
            
            if let oauth = loginResponse.oauth {
                self.oauth = try! JSONDecoder().decode(OAuth.self, from: oauth.data(using: .utf8)!)
                self.OAuthToken = self.oauth!.oauth_token
                self.SteamId = self.oauth!.steamid
                self.InvalidLogin = false
                await self.Refresh()
                return LoginResult.LoginOkay
            }
            
            return LoginResult.GeneralFailure
            
        }
        catch(let e){
            print("An error occured when Login: ", e)
        }
        self.InvalidLogin = true
        return LoginResult.GeneralFailure
    }
    
    func GetConfirmations() async throws{
        let servertime = SteamTimeSync.shared.getServerTime()
        let timeHash: String = CreateTimeHash(time: servertime, tag: "conf")
        let queryList: [String : String] = ["p": self.deviceID, "a": self.SteamId!, "k": timeHash, "t": String(servertime), "m": "android", "tag": "conf"]
        let (data, response) = try await self.Session.callGet(url: COMMUNITY_BASE_URL.appendingPathComponent("/mobileconf/conf"), query: queryList)
        var confList: [Confirmation] = []
        
        guard let httpResponse = response as? HTTPURLResponse,
              httpResponse.statusCode == 200 else {
            throw ErrorType.ERR_INVALID_RESPONSE
        }
        
        let tradeHtml: String = String(data: data, encoding: .utf8)!
        
        // Find the matching capture groups
        let matches = _tradeRegex.matches(
            in: tradeHtml,
            options: [],
            range: NSRange(tradeHtml.startIndex..<tradeHtml.endIndex, in: tradeHtml)
        )
        
        for match in matches {
            let tradeIds: String = String(tradeHtml[Range(match.range(at:1), in: tradeHtml)!])
            let traded = String(tradeHtml[Range(match.range(at:2), in: tradeHtml)!])
            var innerMatch = _tradeConfidRegex.firstMatch(in: tradeIds, range: NSRange(tradeIds.startIndex..<tradeIds.endIndex, in: tradeIds))!
            let id = String(tradeIds[Range(innerMatch.range(at:1), in: tradeIds)!])
            innerMatch = _tradeKeyRegex.firstMatch(in: tradeIds, range: NSRange(tradeIds.startIndex..<tradeIds.endIndex, in: tradeIds))!
            let key = String(tradeIds[Range(innerMatch.range(at:1), in: tradeIds)!])
            innerMatch = _tradePlayerRegex.firstMatch(in: traded, range: NSRange(traded.startIndex..<traded.endIndex, in: traded))!
            
            // To be implemented.
            
        }
        
    }
}

extension URLSession{
    func getPostString(params:[String:Any?]) -> String
    {
        var data = [String]()
        for(key, value) in params
        {
            if let value = value{
                data.append(key + "=\(value)".encoded!)
            }
        }
        return data.map { String($0) }.joined(separator: "&")
    }
    
    func callPost(url:URL, params:[String:Any]) async throws -> (Data, URLResponse) {
        return try await self.callPost(url: url, data: self.getPostString(params: params).data(using: .utf8)!)
    }
    
    func callPost(url:URL, data: Data) async throws -> (Data, URLResponse){
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.httpBody = data
        return try await self.data(for: request)
    }
    
    func callGet(url:URL, query:[String:String]) async throws -> (Data, URLResponse) {
        var request = URLRequest(url: url.appending(querylist: query))
        request.httpMethod = "GET"
        return try await self.data(for: request)
    }
}

extension String{
    
    var encoded: String? {
        var urlB64Encoded: CharacterSet = .urlHostAllowed
        urlB64Encoded.remove(charactersIn: "+")
        return self.addingPercentEncoding(withAllowedCharacters: urlB64Encoded)
    }
}


// https://stackoverflow.com/a/50990443/19450793
extension URL {
    
    func appending(_ queryItem: String, value: String?) -> URL {
        
        guard var urlComponents = URLComponents(string: absoluteString) else { return absoluteURL }
        
        // Create array of existing query items
        var queryItems: [URLQueryItem] = urlComponents.queryItems ??  []
        
        // Create query item
        let queryItem = URLQueryItem(name: queryItem, value: value)
        
        // Append the new query item in the existing query items array
        queryItems.append(queryItem)
        
        // Append updated query items array in the url component object
        urlComponents.queryItems = queryItems
        
        // Returns the url from new url components
        return urlComponents.url!
    }
    
    func appending(querylist: [String: String]) -> URL {
        
        guard var components = URLComponents(string: self.absoluteString) else {return absoluteURL}
        components.queryItems = querylist.map { element in URLQueryItem(name: element.key, value: element.value) }
        
        return components.url!
    }
    
    mutating func appendQueryItem(name: String, value: String?) {
        
        guard var urlComponents = URLComponents(string: absoluteString) else { return }
        
        // Create array of existing query items
        var queryItems: [URLQueryItem] = urlComponents.queryItems ??  []
        
        // Create query item
        let queryItem = URLQueryItem(name: name, value: value)
        
        // Append the new query item in the existing query items array
        queryItems.append(queryItem)
        
        // Append updated query items array in the url component object
        urlComponents.queryItems = queryItems
        
        // Returns the url from new url components
        self = urlComponents.url!
    }
    
    mutating func appendQueryItems(querylist: [String: String]) {
        
        var components = URLComponents(string: self.absoluteString)
        components!.queryItems = querylist.map { element in URLQueryItem(name: element.key, value: element.value) }
        
        self = components!.url!
    }
}
