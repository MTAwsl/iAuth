//
//  Accounts.swift
//  SteamAuth
//
//  Created by Dominic Socular on 2022/6/21.
//

import Foundation

struct SteamAccount: Identifiable{
    let id: UUID
    var name: String
    var key: String
    var Code: String
    private var generator: Authenticator
    init(id: UUID = UUID(), name: String, key: String){
        self.id = id
        self.name = name
        self.key = key
        self.generator = Authenticator(key: key)
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
