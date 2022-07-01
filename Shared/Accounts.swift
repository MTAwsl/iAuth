//
//  Accounts.swift
//  SteamAuth
//
//  Created by Dominic Socular on 2022/6/21.
//

import Foundation

struct SteamData: Codable{
    let shared_secret: String
    let serial_number: String
    let revocation_code: String
    let uri: String
    let server_time: String
    let account_name: String
    let token_gid: String
    let identity_secret: String
    let secret_1: String
    let status: Int
    let steamid: String
    let steamguard_scheme: String
}

struct SteamAccount: Identifiable{
    let id: UUID
    var name: String
    var key: String
    var Code: String
    var DeviceID: String
    var data: SteamData?
    private var generator: Authenticator
    init(id: UUID = UUID(), name: String, key: String, deviceid: String = "", steamdata: String = "{}"){
        self.id = id
        self.name = name
        self.key = key
        self.generator = Authenticator(key: key)
        self.DeviceID = deviceid
        self.data = try? JSONDecoder().decode(SteamData.self, from: steamdata.data(using: .utf8)!)
        self.Code = self.generator.CalculateCode()
    }
    mutating func Update() -> Void{
        self.generator.UpdateKey(key: self.key)
        self.Code = self.generator.CalculateCode()
    }
}

class Accounts{
    static let shared = Accounts()
    var accList : [SteamAccount] = []
    private init(){
        self.append(name:"Test1", key:"aaaaaaaaaaaaaa==")
        self.append(name:"Test2", key:"bbbbbbbbbbbbbb==")
    }
    
    func append(name: String, key: String){
        accList.append(SteamAccount.init(name: name, key: key))
    }
    
    func remove(acc: SteamAccount){
        let index = accList.firstIndex{$0.id == acc.id}!
        accList.remove(at: index)
    }
    
    func UpdateCode() {
        for i in accList.indices{
            accList[i].Update()
        }
    }
    
    func UpdateAcc(acc: SteamAccount){
        if let index = accList.firstIndex(where: {$0.id == acc.id}){
            accList[index] = acc
        }
        else{
            accList.append(acc)
        }
    }
}
