import Zemu, { DEFAULT_START_OPTIONS } from '@zondax/zemu'
import AvalancheApp from '@zondax/ledger-avalanche-app'
import Eth from '@ledgerhq/hw-app-eth'

import path from 'path'
import * as readline from 'node:readline/promises'
import assert from 'assert'

const MODELS = {
  nanos: { name: 'nanos', prefix: 'S', path: path.resolve('../build/output/app_s.elf') },
  nanox: { name: 'nanox', prefix: 'X', path: path.resolve('../build/output/app_x.elf') },
  nanosp: { name: 'nanosp', prefix: 'SP', path: path.resolve('../build/output/app_sp.elf') },
  stax: { name: 'stax', prefix: 'ST', path: path.resolve('../build/output/app_fs.elf') }
}

const MODEL = MODELS["stax"];
const CLA = 0x80
const APP_DERIVATION = "m/44'/9000'/0'/0/0"
const ETH_DERIVATION = "m/44'/60'/0'/0/0"

const seed = 'equip will roof matter pink blind book anxiety banner elbow sun young'

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
      case 'c':
        await sim.fingerTouch({ x: 200, y: 250, delay: 1 })
      default:
        break
    }
  }

  await rl.close()
}
async function callTestFunction(sim, app) {
  const responseReq = app.showWalletId();

  await sim.waitForScreenChanges([], 100000000000)

  await interactiveZemu(sim)

  const response = await responseReq;
  console.log(response)
}

async function main() {
  await beforeStart()

  let model = MODELS["stax"];
  let sim_options = {
    ...DEFAULT_START_OPTIONS,
    logging: true,
    startTimeout: 400000000,
    custom: `-s "${seed}" --color LAGOON_BLUE`,
    model: model.name,
    approveKeyword: model.name === 'stax' ? 'Cancel' : '',
    approveAction: 10, //ApproveTapButton
  };

  if (process.argv.length > 2 && process.argv[2] === 'debug') {
    sim_options['custom'] = sim_options['custom'] + ' --debug'
  }

  const sim = new Zemu.default(model.path)

  try {
    await sim.start(sim_options)
    const app = new AvalancheApp.default(sim.getTransport())

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
