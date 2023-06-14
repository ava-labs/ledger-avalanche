import dts from 'rollup-plugin-dts'
import esbuild from 'rollup-plugin-esbuild'

// Always provide both CJS and ES exports
const config = [
  {
    input: `src/index.ts`,
    plugins: [esbuild()],
    output: [
      {
        dir: 'esm',
        format: 'esm',
        preserveModules: true,
      },
    ],
  },
  {
    input: `src/index.ts`,
    plugins: [dts()],
    output: [
      {
        dir: 'esm',
        format: 'esm',
        preserveModules: true,
      },
    ],
  },
]

export default config
