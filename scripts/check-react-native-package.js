// The React Native package, as `npm pack --dry-run --json` lists it: print what goes out, and
// fail unless both platforms' built libraries are in it. Run by the release workflow.
//
//   node scripts/check-react-native-package.js pack.json
const files = JSON.parse(require('fs').readFileSync(process.argv[2], 'utf8'))[0].files.map(
  (f) => f.path,
);
console.log(files.join('\n'));

const needed = {
  'the Android library for arm64-v8a': /^android\/src\/main\/jniLibs\/arm64-v8a\/.+\.so$/,
  'the Android library for x86_64': /^android\/src\/main\/jniLibs\/x86_64\/.+\.so$/,
  'the generated bindings': /^src\/generated\/.+\.ts$/,
  'the iOS podspec': /^[^/]+\.podspec$/,
  "the iOS framework's Info.plist": /^[^/]+\.xcframework\/Info\.plist$/,
  'the iOS library for devices': /^[^/]+\.xcframework\/ios-arm64\/.+\.a$/,
  'the iOS library for the simulator': /^[^/]+\.xcframework\/ios-arm64-simulator\/.+\.a$/,
};
const missing = Object.entries(needed)
  .filter(([, pattern]) => !files.some((f) => pattern.test(f)))
  .map(([what]) => what);
if (missing.length > 0) {
  console.error(`\nnot in the package: ${missing.join('; ')}`);
  process.exit(1);
}
console.log(`\n${files.length} files, with both platforms' libraries`);
