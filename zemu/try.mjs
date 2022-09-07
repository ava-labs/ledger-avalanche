import TransportNodeHid from '@ledgerhq/hw-transport-node-hid'
import ledger_logs from '@ledgerhq/logs'
import AvalancheApp from '@zondax/ledger-avalanche-app'

async function main() {
  const transport = await TransportNodeHid.default.open();
  ledger_logs.listen((log) => {
    console.log(`${log.type} ${log.message}`)
  });
  const app = new AvalancheApp.default(transport);

  let response = await app.getVersion();
  console.log(response)
}

; (async () => {
  await main()
})()
