# deno-libsodium

With the release of Deno 2.0 the [support for npm packages]((https://docs.deno.com/runtime/fundamentals/node/)) is now available, but this does not work “out-of-the-box” for the [libsodium-wrappers](https://www.npmjs.com/package/libsodium-wrappers) / [libsodium-wrappers-sumo](https://www.npmjs.com/package/libsodium-wrappers-sumo) packages, as the actual functions are only provided after loading the WebAssembly file. Therefore, this small module closes the gap to be able to use sodium as usual!

## Usage

The only difference between the official npm packages and my module is the initial routine. You need to call `await sodium_init()` instead of `await ready`.

## License

[libsodium](https://github.com/jedisct1) uses the [ISC](https://github.com/jedisct1/libsodium.js/blob/master/LICENSE) license while this repository was published under the [MIT](LICENSE.md) license.
