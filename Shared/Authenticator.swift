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
       return (Int64(Date().timeIntervalSince1970) + self.ServerTimeDiff) / 30
    }
    
    func SyncTime(forceResync:Bool=false) -> Void{
        if !forceResync && lastErrorTime >= Int64(Date().timeIntervalSince1970) - 300{
            // Do not retry in 5 minutes
            return
        }
        var request = URLRequest(url:URL(string:SYNC_TIME_URL)!)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("application/json", forHTTPHeaderField: "Content_Type")
        self.timesyncstat = true
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
                    self.lastErrorTime = Int64(Date().timeIntervalSince1970)
                    self.timesyncstat = false;
                    return
                }
                print("Error when Syncing Time: ", err ?? URLError(.badServerResponse))
                self.lastError = ErrorType.ERR_INVALID_RESPONSE
                self.lastErrorTime = Int64(Date().timeIntervalSince1970)
                self.timesyncstat = false;
                return
            }
            guard (200 ... 299) ~= response.statusCode else {
                print("Error when Syncing Time: ")
                print("statusCode should be 2xx, but is \(response.statusCode)")
                print("response = \(response)")
                self.lastError = ErrorType.ERR_INVALID_RESPONSE
                self.lastErrorTime = Int64(Date().timeIntervalSince1970)
                self.timesyncstat = false;
                return
            }
            let decoder = JSONDecoder()
            do{
                let result = try decoder.decode(SERVER_TIME_RESP.self, from: data)
                let curTime = Int64(Date().timeIntervalSince1970)
                self.ServerTimeDiff = curTime - result.Time
                self.lastError = ErrorType.ERR_SUCCESS
                self.lastSyncTime = curTime
                self.timesyncstat = false
                return
            }catch(let err){
                print("Error when Syncing Time:")
                print("Decoding Error:", err)
                self.lastError = ErrorType.ERR_INVALID_JSON
                self.lastErrorTime = Int64(Date().timeIntervalSince1970)
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
        if forceResync || SteamTimeSync.shared.ServerTimeDiff == 0 {
            SteamTimeSync.shared.SyncTime(forceResync: forceResync)
        }
        var hmac = HMAC<Insecure.SHA1>(key: SymmetricKey(data:self.key))
        let time = SteamTimeSync.shared.getServerTime()
        hmac.update(data: withUnsafeBytes(of: time.bigEndian, {Data($0)}))
        let mac = withUnsafeBytes(of: hmac.finalize(), {Data($0)})
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
    
    struct OAuth : Codable
    {
        let steamid: String?
        let oauth_token: String?
        let wgtoken: String?
        let wgtoken_secure: String?
        let webcookie: String?
    }
    
    struct LoginResponse : Decodable
    {
        let success: Bool
        let login_complete: Bool?
        let oauth: OAuth?
        let captcha_gid: String
        let captcha_needed: Bool
        let emailsteamid: String?
        let emailauth_needed: Bool?
        let requires_twofactor: Bool?
        let message: String?
        
        enum CodingKeys: String, CodingKey {
            case success, login_complete, oauth, captcha_gid, captcha_needed, emailsteamid, emailauth_needed, requires_twofactor, message
        }
        
        init(from decoder: Decoder) throws {
            let values = try decoder.container(keyedBy: CodingKeys.self)
            self.captcha_needed = try values.decode(Bool.self, forKey: .captcha_needed)
            self.success = try values.decode(Bool.self, forKey: .success)
            
            if values.contains(.emailauth_needed){
                self.emailauth_needed = try values.decode(Bool.self, forKey: .emailauth_needed)
            }
            else {
                self.emailauth_needed = nil
            }
            
            if values.contains(.emailsteamid){
                self.emailsteamid = try values.decode(String.self, forKey: .emailsteamid)
            }
            else{
                self.emailsteamid = nil
            }
            
            if values.contains(.requires_twofactor){
                self.requires_twofactor = try values.decode(Bool.self, forKey: .requires_twofactor)
            }
            else{
                self.requires_twofactor = nil
            }
        
            if self.captcha_needed{
                self.captcha_gid = try values.decode(String.self, forKey: .captcha_gid)
            }
            else{
                self.captcha_gid = "-1"
            }
            
            if values.contains(.login_complete){
                self.login_complete = try values.decode(Bool.self, forKey: .login_complete)
            }
            else{
                self.login_complete = nil
            }
            
            if values.contains(.oauth){
                self.oauth = try values.decode(OAuth.self, forKey: .oauth)
            }
            else{
                self.oauth = nil
            }
            
            if values.contains(.message){
                self.message = try values.decode(String.self, forKey: .message)
            }
            else{
                self.message = nil
            }
        }
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
    
    init(auth: Authenticator, username: String, password: String, identitySecret: String, deviceId: String){
        self.auth = auth
        self.deviceID = deviceId
        self.sharedSecret = auth.key.base64EncodedString()
        self.identitySecret = identitySecret
        self.username = username.replacingOccurrences(of: "[^\u{0000}-\u{007F}]", with: "", options: .regularExpression)
        self.password = password.replacingOccurrences(of: "[^\u{0000}-\u{007F}]", with: "", options: .regularExpression)
    }
    
    init(sharedsec: String, username: String, password: String, identitySecret: String, deviceId: String){
        self.sharedSecret = sharedsec
        self.identitySecret = identitySecret
        self.deviceID = deviceId
        self.auth = Authenticator(key: sharedsec)
        self.username = username.replacingOccurrences(of: "[^\u{0000}-\u{007F}]", with: "", options: .regularExpression)
        self.password = password.replacingOccurrences(of: "[^\u{0000}-\u{007F}]", with: "", options: .regularExpression)
    }
    
    func CreateTimeHash(time: Int64 = SteamTimeSync.shared.getServerTime(), tag: String) -> String{
        let encData = withUnsafeBytes(of: time.bigEndian, {Data($0)}) + tag.data(using: .utf8)! + Data(count: (24-tag.count > 0) ? (24-tag.count) : 0)
        var hmac = HMAC<Insecure.SHA1>(key: SymmetricKey(data:Data(base64Encoded: self.identitySecret)!))
        hmac.update(data: encData)
        return withUnsafeBytes(of: hmac.finalize(), {Data($0)}).base64EncodedString()
    }
    
    func Login(captchaId: String? = nil, captchaText: String? = nil) async -> LoginResult{
        if self.Session.configuration.httpCookieStorage == nil {
            self.Session.configuration.httpCookieStorage = HTTPCookieStorage()
        }
        let setCookie: (String, String) -> Void = {key, value in
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
        
        // Setting up Cookies
        let initCookies: KeyValuePairs = ["mobileClientVersion": "3067969+%282.1.3%29",
                                          "mobileClient": "android",
                                          "steamid": "",
                                          "steamLogin": "",
                                          "Steam_Language": "english",
                                          "dob": ""
        ]
        for cookie in initCookies{
            setCookie(cookie.key, cookie.value)
        }
        if var headers = self.Session.configuration.httpAdditionalHeaders{
            headers["User-Agent"] = "Mozilla/5.0 (iPhone; CPU iPhone OS 12_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148"
            headers["Accept"] = "text/javascript, text/html, application/xml, text/xml, */*"
            headers["X-Requested-With"] = "com.valvesoftware.android.steam.community"
        }
        else{
            self.Session.configuration.httpAdditionalHeaders = ["X-Requested-With": "com.valvesoftware.android.steam.community", "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 12_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148", "Accept": "text/javascript, text/html, application/xml, text/xml, */*"]
        }
        do{
            let (_, _) = try await self.Session.data(from: COMMUNITY_BASE_URL.appendingPathComponent("/mobilelogin?oauth_client_id=DE45CD61&oauth_scope=read_profile write_profile read_client write_client"))
        
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
            let loginResponse: LoginResponse = try! JSONDecoder().decode(LoginResponse.self, from: data)

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
            
            if (loginResponse.captcha_needed)
            {
                self.RequireCaptcha = true;
                self.CaptchaId = loginResponse.captcha_gid;
                self.InvalidLogin = true
                return LoginResult.NeedCaptcha;
            }
            
            if let _ = loginResponse.emailauth_needed
            {
                self.RequiresEmail = true;
                self.SteamId = loginResponse.emailsteamid;
                self.InvalidLogin = true
                return LoginResult.NeedEmail;
            }
            
            if let b2fa = loginResponse.requires_twofactor
            {
                if b2fa && !loginResponse.success {
                    self.Require2FA = true;
                    self.InvalidLogin = true
                    return LoginResult.Need2FA;
                }
            }
            
            guard ((loginResponse.oauth != nil) && loginResponse.oauth!.oauth_token != nil && (loginResponse.oauth!.oauth_token!.count) > 0) else
            {
                self.InvalidLogin = true
                return LoginResult.GeneralFailure;
            }
            
            if (loginResponse.login_complete == nil || loginResponse.login_complete == false)
            {
                self.InvalidLogin = true
                return LoginResult.BadCredentials;
            }
            
            if let oauth = loginResponse.oauth {
                self.OAuthToken = oauth.oauth_token
                self.SteamId = oauth.steamid
                self.InvalidLogin = false
                return LoginResult.LoginOkay
            }
            
        }
        catch(let e){
            print("An error occured when Login: ", e)
        }
        self.InvalidLogin = true
        return LoginResult.GeneralFailure
    }
    
    func GetConfirmations() async throws{
        let timeHash: String = CreateTimeHash(tag: "conf")
        let postData: [String : Any] = ["p": self.deviceID, "a": self.SteamId!, "k": timeHash, "t": SteamTimeSync.shared.getServerTime(), "m": "android", "tag": "conf"]
        let (data, response) = try await self.Session.callGet(url: COMMUNITY_BASE_URL.appendingPathComponent("/mobileconf/conf"), query: postData as [String : Any])
        guard let httpResponse = response as? HTTPURLResponse,
              httpResponse.statusCode == 200 else {
            throw ErrorType.ERR_INVALID_RESPONSE
        }
        print(data)
    }
}

extension URLSession{
    func getPostString(params:[String:Any?]) -> String
    {
        var data = [String]()
        for(key, value) in params
        {
            if let value = value{
                data.append(key + "=\(value)")
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
    
    func callGet(url:URL, query:[String:Any]) async throws -> (Data, URLResponse) {
        var request = URLRequest(url: url.appendingPathExtension("?\(self.getPostString(params: query).data(using: .utf8)!)"))
        request.httpMethod = "GET"
        return try await self.data(for: request)
    }
}
