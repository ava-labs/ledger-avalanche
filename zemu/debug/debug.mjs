import Zemu from '@zondax/zemu'
import AvalancheApp from '@zondax/ledger-avalanche-app'
import Eth from '@ledgerhq/hw-app-eth'
import path from 'path'
import * as readline from 'node:readline/promises'

const APP_PATH = path.resolve('../build/output/app_s.elf')
const CLA = 0x80
const APP_DERIVATION = "m/44'/9000'/0'"
const ETH_DERIVATION = "m/44'/60'/0'/0/0"

const seed = 'equip will roof matter pink blind book anxiety banner elbow sun young'
const SIM_OPTIONS = {
  logging: true,
  // startDelay: 400000,
  startTimeout: 400000,
  startText: "Ready",
  custom: `-s "${seed}" --color LAGOON_BLUE`,
  model: 'nanos',
}

async function beforeStart() {
  process.on('SIGINT', () => {
    Zemu.default.stopAllEmuContainers(function () {
      process.exit()
    })
  })
  await Zemu.default.checkAndPullImage()
}

async function beforeEnd() {
  await Zemu.default.stopAllEmuContainers()
}

async function debugScenario1(sim, app) {
  // Here you can customize what you want to do :)
}

async function interactiveZemu(sim) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout })

  let answer

  while (answer != 'q') {
    answer = await rl.question('enter command [j, k, jk, q]: ')

    switch (answer) {
      case 'j':
        await sim.clickLeft(undefined, false)
        break
      case 'k':
        await sim.clickRight(undefined, false)
        break
      case 'jk':
        await sim.clickBoth(undefined, false)
        break
      default:
        break
    }
  }

  await rl.close()
}

async function callTestFunction(sim, app) {
  let responseReq = app.signTransaction(ETH_DERIVATION, '02f5018402a8af41843b9aca00850d8c7b50e68303d090944a2962ac08962819a8a17661970e3c0db765565e8817addd0864728ae780c0')
  await sim.waitScreenChange(100000000)

  await interactiveZemu(sim)

  const response = await responseReq;

  console.log(response)
}

async function main() {
  await beforeStart()

  if (process.argv.length > 2 && process.argv[2] === 'debug') {
    SIM_OPTIONS['custom'] = SIM_OPTIONS['custom'] + ' --debug'
  }

  const sim = new Zemu.default(APP_PATH)

  try {
    await sim.start(SIM_OPTIONS)
    const app = new Eth.default(sim.getTransport())

    ////////////
    /// TIP you can use zemu commands here to take the app to the point where you trigger a breakpoint

    await callTestFunction(sim, app)

    /// TIP
  } finally {
    await sim.close()
    await beforeEnd()
  }
}

; (async () => {
  await main()
})()
