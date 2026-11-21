const path = require('path');
const pkg = require('../package.json');

module.exports = {
  project: {
    ios: {
      automaticPodsInstallation: true,
    },
  },
  dependencies: {
    // The C++ the generated library is built on. Its pod is asked for at the exact version of
    // the npm package, and CocoaPods does not always have that one (0.31.0-7 is on npm only),
    // so iOS takes it from node_modules. Android includes its headers by path and links nothing.
    'uniffi-bindgen-react-native': {
      root: path.join(__dirname, '..', 'node_modules', 'uniffi-bindgen-react-native'),
      platforms: {
        ios: {},
        android: null,
      },
    },
    [pkg.name]: {
      root: path.join(__dirname, '..'),
      platforms: {
        // Codegen script incorrectly fails without this
        // So we explicitly specify the platforms with empty object
        ios: {},
        android: {},
      },
    },
  },
};
