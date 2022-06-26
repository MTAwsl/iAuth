//
//  EditView.swift
//  SteamAuth
//
//  Created by Dominic Socular on 2022/6/26.
//

import SwiftUI

struct EditView: View {
    @Binding var acc : SteamAccount

    var body: some View {
        VStack{
            HStack{
                Text("Name:")
                TextField("Name", text: $acc.name)
            }
            HStack{
                Text("Key:")
                TextField("Key", text: $acc.key)
            }
        }.padding().fixedSize()
    }
}
