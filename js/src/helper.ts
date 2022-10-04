import { decode as bs58_decode } from 'bs58'

const HARDENED = 0x80000000

export function pathCoinType(path: string): string {
  if (!path.startsWith('m')) {
    throw new Error('Path should start with "m" (e.g "m/44\'/5757\'/5\'/0/3")')
  }

  //skip the first element (m)
  const pathArray = path.split('/').slice(1)

  const maybe44 = Number(pathArray[0].slice(0, -1))
  if (maybe44 != 44) {
    throw new Error(`Path's first element should be "44", got ${maybe44} (e.g "m/44'/5757'/5'/0/3")`)
  }

  return pathArray[1]
}

export function serializePath(path: string): Buffer {
  if (!path.startsWith('m')) {
    throw new Error('Path should start with "m" (e.g "m/44\'/5757\'/5\'/0/3")')
  }

  const pathArray = path.split('/')

  if (pathArray.length !== 6 && pathArray.length !== 5 && pathArray.length !== 4) {
    throw new Error("Invalid path. (e.g \"m/44'/5757'/5'/0/3\")")
  }

  const buf = Buffer.alloc(1 + (pathArray.length - 1) * 4)
  buf.writeUInt8(pathArray.length - 1) //first byte is the path length

  for (let i = 1; i < pathArray.length; i += 1) {
    let value = 0
    let child = pathArray[i]
    if (child.endsWith("'")) {
      value += HARDENED
      child = child.slice(0, -1)
    }

    const childNumber = Number(child)

    if (Number.isNaN(childNumber)) {
      throw new Error(`Invalid path : ${child} is not a number. (e.g "m/44'/461'/5'/0/3")`)
    }

    if (childNumber >= HARDENED) {
      throw new Error('Incorrect child value (bigger or equal to 0x80000000)')
    }

    value += childNumber

    buf.writeUInt32BE(value, 1 + 4 * (i - 1))
  }

  return buf
}

export function serializePathSuffix(path: string): Buffer {
  if (path.startsWith('m')) {
    throw new Error('Path suffix do not start with "m" (e.g "0/3")')
  }

  const pathArray = path.split('/')

  if (pathArray.length !== 2) {
    throw new Error('Invalid path suffix. (e.g "0/3")')
  }

  const buf = Buffer.alloc(1 + pathArray.length * 4)
  buf.writeUInt8(pathArray.length) //first byte is the path length

  for (let i = 0; i < pathArray.length; i += 1) {
    let value = 0
    const child = pathArray[i]

    if (child.endsWith("'")) {
      throw new Error('Invalid hardened path suffix. (e.g "0/3")')
    }

    const childNumber = Number(child)

    if (Number.isNaN(childNumber)) {
      throw new Error(`Invalid path : ${child} is not a number. (e.g "0/3")`)
    }

    if (childNumber >= HARDENED) {
      throw new Error('Incorrect child value (bigger or equal to 0x80000000)')
    }

    value += childNumber

    buf.writeUInt32BE(value, 1 + 4 * i)
  }

  return buf
}

export function serializeHrp(hrp?: string): Buffer {
  if (hrp) {
    const bufHrp = Buffer.from(hrp, 'ascii')
    return Buffer.concat([Buffer.alloc(1, bufHrp.length), bufHrp])
  } else {
    return Buffer.alloc(1, 0)
  }
}

export function serializeChainID(chainid?: string): Buffer {
  if (chainid) {
    let decoded = bs58_decode(chainid)
    if (decoded.length == 36) {
      //chop checksum off
      decoded = decoded.slice(0, 32)
    } else if (decoded.length != 32) {
      throw Error('ChainID was not 32 bytes long (encoded with base58)')
    }

    return Buffer.concat([Buffer.alloc(1, decoded.length), decoded])
  } else {
    return Buffer.alloc(1, 0)
  }
}
