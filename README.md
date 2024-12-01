# deno-libsodium

With the release of Deno 2.0 the [support for npm packages]((https://docs.deno.com/runtime/fundamentals/node/)) is now available, but this does not work “out-of-the-box” for the [libsodium-wrappers](https://www.npmjs.com/package/libsodium-wrappers) package, as the actual functions are only provided after loading the WebAssembly file. Therefore, this small module closes the gap to be able to use sodium as usual!

## Usage

All functions, interfaces and constants were taken from [@types/libsodium-wrappers](https://github.com/DefinitelyTyped/DefinitelyTyped/blob/master/types/libsodium-wrappers/index.d.ts) with a few non functional related changes. The only difference is the initial routine, you need to call `await sodium_init()` now instead of `await ready`.

## License

[libsodium](https://github.com/jedisct1) uses the [ISC](https://github.com/jedisct1/libsodium.js/blob/master/LICENSE) license while this repository was published under the [MIT](LICENSE.md) license.
