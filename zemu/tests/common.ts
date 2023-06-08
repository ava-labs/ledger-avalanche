import { DEFAULT_START_OPTIONS, IDeviceModel, ButtonKind } from '@zondax/zemu'

const Resolve = require('path').resolve

export const APP_SEED = 'equip will roof matter pink blind book anxiety banner elbow sun young'

const APP_PATH_S = Resolve('../build/output/app_s.elf')
const APP_PATH_X = Resolve('../build/output/app_x.elf')
const APP_PATH_SP = Resolve('../build/output/app_sp.elf')
const APP_PATH_ST = Resolve('../build/output/app_fs.elf')

export const models: IDeviceModel[] = [
  { name: 'nanos', prefix: 'S', path: APP_PATH_S },
  { name: 'nanox', prefix: 'X', path: APP_PATH_X },
  { name: 'nanosp', prefix: 'SP', path: APP_PATH_SP },
  { name: 'stax', prefix: 'ST', path: APP_PATH_ST },
]

export const defaultOptions = (m: IDeviceModel) => {
  return {
    ...DEFAULT_START_OPTIONS,
    logging: true,
    custom: `-s "${APP_SEED}"`,
    approveKeyword: m.name === 'stax' ? 'Cancel' : '',
    approveAction: ButtonKind.ApproveTapButton,
    model: m.name,
  }
}

export const ROOT_PATH = "m/44'/9000'/0'"
export const APP_DERIVATION = "m/44'/9000'/0'/0/0"
export const ETH_DERIVATION = "m/44'/60'/0'/0'"

type MapCartesian<T extends any[][]> = {
  [P in keyof T]: T[P] extends Array<infer U> ? U : never
}

export const cartesianProduct = <T extends any[][]>(...arr: T): MapCartesian<T>[] =>
  arr.reduce((a, b) => a.flatMap(c => b.map(d => [...c, d])), [[]]) as MapCartesian<T>[]
