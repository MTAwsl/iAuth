//
//  Authenticator.swift
//  SteamAuth
//
//  Created by Dominic Socular on 2022/6/19.
//

import Foundation
import CryptoKit

class SteamTimeSync{
    static let shared = SteamTimeSync()
    let SYNC_TIME_URL = "https://api.steampowered.com:443/ITwoFactorService/QueryTime/v0001"
    var ServerTimeDiff: Int64 = 0
    var timesyncstat: Bool = false // Is timesyncing in progress?
    var lastSyncTime: Int64 = 0
    var lastError: ErrorType = ErrorType.ERR_SUCCESS
    var lastErrorTime:Int64 = 0
    
    private struct SERVER_TIME_RESP: Decodable {
        let Time : Int64
        let SkewToleranceSeconds: uint32
        let LargeTimeJink : uint32
        let ProbeFrequencySeconds:uint32
        let AdjustedTimeProbeFrequencySeconds:uint32
        let HintProbeFrequencySeconds:uint32
        let SyncTimeout:uint32
        let TryAgainSeconds:uint32
        let MaxAttempts: uint32
    }

    enum ErrorType{
        case ERR_SUCCESS
        case ERR_NETWORK_TIMEOUT
        case ERR_INVALID_RESPONSE
        case ERR_INVALID_JSON
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
    let COMMUNITY_BASE_URL = "https://steamcommunity.com/"
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
