

use common_types::ipc::{IpcRequest, IpcReply, query_account_info};
use common_types::transaction::{UnverifiedTransaction};
use account_lib::Account;
use account_lib::pre_sign_tx;
use zmq::{Socket, Context, DEALER, ROUTER, DONTWAIT};
use std::time::Duration;
use hex_literal::hex;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};

fn main() {

    let a0 = Account{
        address:"26d1ec50b4e62c1d1a40d16e7cacc6a6580757d5".to_string(),
        secret:"17d08f5fe8c77af811caa0c9a187e668ce3b74a99acc3f6d976f075fa8e0be55".to_string(),
        public:"689268c0ff57a20cd299fa60d3fb374862aff565b20b5f1767906a99e6e09f3ff04ca2b2a5cd22f62941db103c0356df1a8ed20ce322cab2483db67685afd124".to_string(),
        nonce:"0".to_string(),
    };
    let a1 = Account{
        address:"fff7e25dff2aa60f61f9d98130c8646a01f31649".to_string(),
        secret:"2075b1d9c124ea673de7273758ed6de14802a9da8a73ceb74533d7c312ff6acd".to_string(),
        public:"48dbce4508566a05509980a5dd1335599fcdac6f9858ba67018cecb9f09b8c4066dc4c18ae2722112fd4d9ac36d626793fffffb26071dfeb0c2300df994bd173".to_string(),
        nonce:"0".to_string(),
    };
    let a2 = Account{
        address:"00cf3711cbd3a1512570639280758118ba0b2bcb".to_string(),
        secret:"001ce488d50d2f7579dc190c4655f32918d505cee3de63bddc7101bc91c0c2f0".to_string(),
        public:"4e19a5fdae82596e1485c69b687c9cc52b5078e5b0668ef3ce8543cd90e712cb00df822489bc1f1dcb3623538a54476c7b3def44e1a51dc174e86448b63f42d0".to_string(),
        nonce:"0".to_string(),
    };
    let a3 = Account{
        address:"32c51b238170c2788ab179099ac70afa9f51351b".to_string(),
        secret:"291dd826cf4a0a95317e2061437128c881268e814847a325847eddde6968c38f".to_string(),
        public:"535c6abc6e20a4b71b7a695004fa50dde32c023d876469340026f91b7dd7f0cb8eafc8d9083a9ab34b303d0b6bf172816615a15a52222c339cfdfc7f9e002558".to_string(),
        nonce:"0".to_string(),
    };
    let a4 = Account{
        address:"1bf672b787263f0639baba61532e1baedd6bcd56".to_string(),
        secret:"b0dcf619c22af722140c515df0f7ac86fe15e65921a0f8f404d876b652be45c6".to_string(),
        public:"f61d5f430c059fda164dd5541e39d1c4e014056ce9123d30bcdfe4fcd025bfd4e6e265e424488de5f17b47578123221bdf134519b1b7fe813bd84891849bdfa7".to_string(),
        nonce:"0".to_string(),
    };
    let a5 = Account{
        address:"3b4942e717358d07b6a8300099ddeb5c137d7192".to_string(),
        secret:"5957687117732f73a378fb6aacabd620d30013577e6270223943cd70a6a95360".to_string(),
        public:"6bfb77cb5d5a3b224ef9cd6f371f53db5e3c334459ea810ef5e8d2e659ff719c6e083c89f89989a5427c56895c0cbd89bab361625587cc48bfbc1073c8950dab".to_string(),
        nonce:"0".to_string(),
    };
    let a6 = Account{
        address:"0acc41d732f605910db67da194f8c4c19dc8775e".to_string(),
        secret:"b4179cc97245d04215434670cca3a8730426afbfd611314eb7a7e4b90e6a6722".to_string(),
        public:"ed638a53820470d0517a06daee45e66a08fbb1102bb9d47f7a66417a3c8241cf241c10a861f7c1a7b70ec8578e8d93a4f7241e3521e7bd03a229c30bdb08c89d".to_string(),
        nonce:"0".to_string(),
    };
    let a7 = Account{
        address:"20cd8edc9ac16876b021b4fa2bafea7afb7895d9".to_string(),
        secret:"446d875997814062f0e49fb33e8d04e41bfa7bd5a535d619f82cd11550fd201a".to_string(),
        public:"01e087edffbbe9ecf60809be7f2f19cbbc6e8a9f9ff5c9f16762bb5d657497cf4bcfc36f8e47dd78ef7ffceb366910c312ab89bc09a742ab3a1c08f6f40cdb22".to_string(),
        nonce:"0".to_string(),
    };
    let a8 = Account{
        address:"7dd58708a7434d6b219c4f37b5e2126043596afa".to_string(),
        secret:"01b8148f6a6d0a2f21bc9aa91fd9a6016fa76f4899cedb8458626612bc13d4a2".to_string(),
        public:"d6acdea97145ac2017e39ca15800b90831ca6294845230096716bfd0cf0e5d51993d01d500e2b10c870400322cd77007ca4a769aefee8f09b617d8e6af03c88c".to_string(),
        nonce:"0".to_string(),
    };
    let a9 = Account{
        address:"5e2d5b34ae700a932314d30d9c0b99d703389aeb".to_string(),
        secret:"1a12a12aa194958bc2f0cbd2131f0f585e265dec9ffcddd85993f71104cf8e0f".to_string(),
        public:"df03baba0d8f1925824502be72bf95435dea30dc68866a857babbadbc04eac26773038777f7ecf61096ecb8f4df0d46d7ba10385a482260c8df27c5bb3cee3bb".to_string(),
        nonce:"0".to_string(),
    };

    let mut accounts = vec![a0, a1, a2, a3, a4, a5, a6, a7, a8, a9];

    use rand::{thread_rng, Rng};
    let mut rng = thread_rng();
    let mut x: usize;
    let mut y : usize;
    let mut z : usize;
    let context = Context::new();
    let socket = context.socket(DEALER).unwrap();
    socket.set_identity( &hex!("1234").to_vec() ).unwrap();
    socket.connect("tcp://127.0.0.1:7050").unwrap();
    let mut count : u128 = 0;
    loop {
        x = 0;
        y = 0;
        while (x == y) {
            x = rng.gen_range(0, 10);
            y = rng.gen_range(0, 10);
        }
        z = (count % 10 + 1) as usize;
        count += 1;
        println!("random x and y : {}, {}; z : {}", x, y, z);

        let receiver = &accounts[y].clone();
        let sender = &mut accounts[x]; // TODO query_sender_nonce(accounts[x].address) and then set
        let tx = pre_sign_tx(sender, receiver);
        send_to_txpool(&socket, tx.as_str(), 3);

        let receiver = &accounts[z].clone();
        let sender = &mut accounts[0];   // TODO query_sender_nonce(accounts[0].address) and then set
        let tx = pre_sign_tx(sender, receiver);
        send_to_txpool(&socket, tx.as_str(), 3);
    }
}

fn send_to_txpool(socket : &Socket, tx : &str, seconds : u64) {
    let foo : UnverifiedTransaction = rlp::decode(&hex::decode(tx).unwrap()).unwrap();
    println!("{:?}", foo);
    let foobar_vec = vec![foo];
    let foobar_bytes = rlp::encode_list(&foobar_vec);

    let ipc_request = IpcRequest {
        method: "SendToTxPool".to_string(),
        id: 666,
        params: foobar_bytes,
    };
    let recovered_request : IpcRequest = rlp::decode(&ipc_request.rlp_bytes()).unwrap();
    println!("Recovered request: {:x?}", recovered_request);

    socket.send(ipc_request.rlp_bytes(), 0).unwrap();
    std::thread::sleep(std::time::Duration::from_secs(seconds));

    let result_rmp = socket.recv_multipart(DONTWAIT);
    if let Ok(mut rmp) = result_rmp {
        println!("Client received from server, Received multiparts: {:?}", rmp);
        let foo : IpcReply = rlp::decode(&rmp.pop().unwrap()).unwrap();
        println!("Client received from server, IpcReply decoded: {:?}", foo);
        let bar : String = rlp::decode(&foo.result).unwrap();
        println!("Client received from server,  Result decoded: {:?}", bar);
    } else {
        println!("Error: Reply Timeout");
    }
}





