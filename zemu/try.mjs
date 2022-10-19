import TransportNodeHid from '@ledgerhq/hw-transport-node-hid'
import ledger_logs from '@ledgerhq/logs'
import AvalancheApp from '@zondax/ledger-avalanche-app'

const APP_DERIVATION = "m/44'/9000'/0'/0/0"

async function main() {
    const transport = await TransportNodeHid.default.open();
    ledger_logs.listen((log) => {
        console.log(`${log.type} ${log.message}`)
    });
    const app = new AvalancheApp.default(transport);
    const resp = await app.getAddressAndPubKey(APP_DERIVATION, true)

    console.log(resp)
}

; (async () => {
  await main()
})()
