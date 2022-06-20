use ledger_app::handle_apdu;

fn main() {
    loop {
        honggfuzz::fuzz!(|data: &[u8]| {
            let mut flags = 0;
            let mut tx = 0;

            let mut data = data.to_vec();
            data.resize(260, 0);

            handle_apdu(&mut flags, &mut tx, data.len() as u32, &mut data[..])
        });
    }
}
