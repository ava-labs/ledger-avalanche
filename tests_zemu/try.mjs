import TransportNodeHid from '@ledgerhq/hw-transport-node-hid'
import ledger_logs from '@ledgerhq/logs'
import AvalancheApp from '@zondax/ledger-avalanche-app'

const APP_DERIVATION = "m/44'/9000'/0'/0/0"

async function get_avax_address(app) {
  const resp = await app.getAddressAndPubKey(APP_DERIVATION, true)

  console.log(resp)
}

async function your_test() {
  console.log('your_result')
}

async function main() {
  const transport = await TransportNodeHid.default.open()
  ledger_logs.listen(log => {
    console.log(`${log.type} ${log.message}`)
  })
  const app = new AvalancheApp.default(transport)

  await your_test()
}

;(async () => {
  await main()
})()
