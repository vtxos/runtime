const path = require('path');
const { getDefaultConfig } = require('@react-native/metro-config');
const { withMetroConfig } = require('react-native-monorepo-config');

const root = path.resolve(__dirname, '..');

/**
 * Metro configuration
 * https://facebook.github.io/metro/docs/configuration
 *
 * @type {import('metro-config').MetroConfig}
 */
const config = withMetroConfig(getDefaultConfig(__dirname), {
  root,
  dirname: __dirname,
  conditions: ['vtxos-react-native-wallet-source'],
});

// rust/ is the client's Rust and its target/ directory, which runs to tens of gigabytes. None of
// it is JavaScript, so Metro never crawls it.
const RUST = new RegExp(
  `^${path.join(root, 'rust').replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}/.*`
);
config.resolver.blockList = [].concat(config.resolver.blockList ?? [], RUST);

module.exports = config;
