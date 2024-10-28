import Eth from '@ledgerhq/hw-app-eth'
import TransportNodeHid from '@ledgerhq/hw-transport-node-hid'
// import ledger_logs from '@ledgerhq/logs'
import { log } from '@ledgerhq/logs'
import AvalancheApp from '@zondax/ledger-avalanche-app'

const APP_DERIVATION = "m/44'/9000'/0'/0/0"
const ETH_DERIVATION = "m/44'/60'/0'/0'"

async function get_avax_address(app: AvalancheApp) {
  const resp = await app.getAddressAndPubKey(APP_DERIVATION, true)
  console.log(resp)
}

async function sign_191_message(app: Eth) {
  // Initialize array to hold the message content
  const msgRaw: number[] = []
  // Add content following the same pattern as the Rust test
  msgRaw.push(...Buffer.from('Hello, ', 'utf8'))
  msgRaw.push(0x80)
  msgRaw.push(...Buffer.from('World! ', 'utf8'))
  msgRaw.push(0x81)
  msgRaw.push(...Buffer.from('This is a ', 'utf8'))
  msgRaw.push(0x82)
  msgRaw.push(...Buffer.from('complex ', 'utf8'))
  msgRaw.push(0x83)
  msgRaw.push(...Buffer.from('test ', 'utf8'))
  msgRaw.push(0x84)
  msgRaw.push(...Buffer.from('vector with ', 'utf8'))
  msgRaw.push(0x85, 0x86, 0x87)
  msgRaw.push(...Buffer.from(' multiple non-ASCII ', 'utf8'))
  msgRaw.push(0x88, 0x89)
  msgRaw.push(...Buffer.from(' characters ', 'utf8'))
  msgRaw.push(0x8a)
  msgRaw.push(...Buffer.from('scattered ', 'utf8'))
  msgRaw.push(0x8b)
  msgRaw.push(...Buffer.from('throughout. ', 'utf8'))
  msgRaw.push(0x8c, 0x8d, 0x8e, 0x8f)
  msgRaw.push(...Buffer.from('It should ', 'utf8'))
  msgRaw.push(0x90)
  msgRaw.push(...Buffer.from('properly ', 'utf8'))
  msgRaw.push(0x91)
  msgRaw.push(...Buffer.from('chunk ', 'utf8'))
  msgRaw.push(0x92)
  msgRaw.push(...Buffer.from('and format.', 'utf8'))

  const msgData = Buffer.from(msgRaw)
  const respReq = await app.signPersonalMessage(ETH_DERIVATION, msgData.toString('hex'))
  console.log('done!')
}

async function main() {
  const transport = await TransportNodeHid.create() // Changed from .open(null)

  log('trying to connect to device')

  const app = new Eth(transport)
  await sign_191_message(app)
}

;(async () => {
  await main().catch(console.error)
})()
