//
//  ViewModel.swift
//  SteamAuth
//
//  Created by Dominic Socular on 2022/6/21.
//

import Foundation
import SwiftUI


@MainActor
private class AuthViewModel: ObservableObject{
    @Published var accounts: [SteamAccount] = []
    
    func UpdateCodes() {
        Accounts.shared.UpdateCode()
        accounts = Accounts.shared.accList
    }
    
}

struct CodeListView: View {
    @StateObject fileprivate var viewModel = AuthViewModel()
    @State private var bMov = false
    @State private var bCopyAlert = false
    @State private var bDeleteAlert = false
    @State private var bEditView = false
    @State private var selectedAcc: SteamAccount?
    
    let timer = Timer.publish(every: 1, on: .main, in: .common).autoconnect()
    var body: some View {
        VStack(alignment:.center){
            List(){
                ForEach(viewModel.accounts){ acc in
                    VStack(alignment: .leading){
                        HStack(alignment:.top, spacing: .zero){
                            Image("SteamAuthenticatorIcon").resizable().aspectRatio(contentMode: .fit)
                            Spacer().frame(width:5)
                            VStack(alignment: .leading){
                                Text("\(acc.name)").fontWeight(.semibold)
                                Text("\(acc.Code)").font(.system(size: 30)).onTapGesture {
                                    bCopyAlert = true
                                    NSPasteboard.general.clearContents()
                                    NSPasteboard.general.setString(acc.Code, forType: .string)
                                }.alert("Code Copied!", isPresented: $bCopyAlert) {
                                    Button("Got it!"){}
                                }
                            }
                            Spacer()
                            VStack(){
                                Spacer()
                                Button("Trades") {}
                            }
                        }.frame(height: 50)
                        Divider()
                    }.contextMenu(){
                        Button("Copy Code"){
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(acc.Code, forType: .string)
                        }
                        Button("Confirmations"){}
                        Divider()
                        Button("Edit"){
                            selectedAcc = acc
                            bEditView = true
                        }
                        Button("Delete"){
                            selectedAcc = acc
                            bDeleteAlert = true
                        }
                    }.confirmationDialog("Confirm Deleteion", isPresented:$bDeleteAlert){
                        Button("Delete", role: .destructive) {
                            withAnimation(.easeInOut) {
                                Accounts.shared.remove(acc: selectedAcc!)
                            }
                        }
                    }message:{
                        Text("You cannot undo this action")
                    }
                }.onMove(){
                    bMov = !bMov
                    Accounts.shared.accList.move(fromOffsets: $0, toOffset: $1 )
                    viewModel.UpdateCodes()
                }
                Text(selectedAcc?.name ?? "").hidden() // Add this to prevent some fucking bug which cannot assign a value to selectedAcc. https://developer.apple.com/forums/thread/652080
            }
            .animation(.easeOut, value: bMov)
            .listStyle(.plain)
            .sheet(isPresented: $bEditView){
                NavigationView {
                    EditView(acc: Binding($selectedAcc)!)
                        .navigationTitle("Edit Account")
                        .toolbar {
                            ToolbarItem(placement: .confirmationAction) {
                                Button("Done") {
                                    Accounts.shared.UpdateAcc(acc: selectedAcc!)
                                    bEditView = false
                                }
                            }
                            ToolbarItem(placement: .cancellationAction) {
                                Button("Cancel") {
                                    bEditView = false
                                }
                            }
                        }
                }.fixedSize()
            }
        }.frame(minWidth: 300, idealWidth: 300, maxWidth: 300, minHeight: 100, idealHeight: 1000, maxHeight: 1000, alignment: .center)
        .onReceive(self.timer){ _ in
            viewModel.UpdateCodes()
        }.toolbar{
            Button("+"){
                selectedAcc = SteamAccount(name: "New Account", key: "ExampleKey==")
                bEditView = true
            }.frame(alignment: .topTrailing).padding(.trailing, 10)
        }.navigationTitle("Authenticator")
        
        Button("TEST"){
            let cli = SteamClient(sharedsec: "---REDACTED---", username: "---REDACTED---", password: "---REDACTED---", identitySecret: "---REDACTED---", deviceId: "---REDACTED---")
            Task{
                var result = await cli.Login()
                while result != .LoginOkay{
                    if result == .LoginOkay{
                        print("LoginSuccessful!")
                        break
                    }
                    if result == .NeedCaptcha{
                        print("Captcha GID: \(cli.captchaGid()!)")
                        print("Link: https://steamcommunity.com/public/captcha.php?gid=\(cli.captchaGid()!)")
                        print("Message: \(cli.getMessage()!)")
                        result = await cli.Login(captchaId: cli.captchaGid()!, captchaText: readLine())
                    }
                    else{
                        print("Message: \(cli.getMessage()!)")
                    }
                }
                try await cli.GetConfirmations()
            }
        }
    }
}

struct CodeListView_Preview: PreviewProvider{
    static var previews: some View{
        CodeListView()
            
    }
}
