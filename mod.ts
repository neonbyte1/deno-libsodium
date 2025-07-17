/**
 * @module
 *
 * This module closes the gap between the npm package and deno.
 *
 * @example
 * ```ts
 * import { sodium_init } from "jsr:@neonbyte/libsodium";
 *
 * await sodium_init();
 * ```
 */
import * as sodium from "npm:libsodium-wrappers-sumo@0.7.15";

/**
 * Enum for Base64 variants used in encoding/decoding.
 */
export enum Base64Variants {
  /** Standard Base64 with padding. */
  ORIGINAL,
  /** Standard Base64 without padding. */
  ORIGINAL_NO_PADDING,
  /** URL-safe Base64 with padding. */
  URLSAFE,
  /** URL-safe Base64 without padding. */
  URLSAFE_NO_PADDING,
}

/**
 * Output format type for Uint8Array outputs.
 */
export type Uint8ArrayOutputFormat = "uint8array";

/**
 * Output format type for string outputs.
 */
export type StringOutputFormat = "text" | "hex" | "base64";

/**
 * Key type for cryptographic operations.
 */
export type KeyType = "curve25519" | "ed25519" | "x25519";

/**
 * Generic structure for a cryptographic box.
 * @template T - The type of data (Uint8Array or string).
 */
interface GenericCryptoBox<T extends Uint8Array | string> {
  /** The encrypted ciphertext. */
  ciphertext: T;
  /** The message authentication code (MAC). */
  mac: T;
}

/** Cryptographic box with Uint8Array format. */
export type CryptoBox = GenericCryptoBox<Uint8Array>;

/** Cryptographic box with string format. */
export type StringCryptoBox = GenericCryptoBox<string>;

/**
 * Generic structure for a secret box.
 * @template T - The type of data (Uint8Array or string).
 */
interface GenericSecretBox<T extends Uint8Array | string> {
  /** The encrypted cipher text. */
  cipher: T;
  /** The message authentication code (MAC). */
  mac: T;
}

/** Secret box with Uint8Array format. */
export type SecretBox = GenericSecretBox<Uint8Array>;

/** Secret box with string format. */
export type StringSecretBox = GenericSecretBox<string>;

/**
 * Generic structure for a cryptographic key exchange.
 * @template T - The type of data (Uint8Array or string).
 */
interface GenericCryptoKX<T extends Uint8Array | string> {
  /** The encrypted ciphertext. */
  ciphertext: T;
  /** Shared receive key. */
  sharedRx: T;
  /** Shared transmit key. */
  sharedTx: T;
}

/** Cryptographic key exchange with Uint8Array format. */
export type CryptoKX = GenericCryptoKX<Uint8Array>;

/** Cryptographic key exchange with string format. */
export type StringCryptoKX = GenericCryptoKX<string>;

/**
 * Generic structure for a key pair.
 * @template T - The type of key data (Uint8Array or string).
 */
interface GenericKeyPair<T extends Uint8Array | string> {
  /** The type of key. */
  keyType: KeyType;
  /** The private key. */
  privateKey: T;
  /** The public key. */
  publicKey: T;
}

/** Key pair with Uint8Array format. */
export type KeyPair = GenericKeyPair<Uint8Array>;

/** Key pair with string format. */
export type StringKeyPair = GenericKeyPair<string>;

/**
 * Generic structure for a tagged message.
 * @template T - The type of data (Uint8Array or string).
 */
interface GenericTag<T extends Uint8Array | string> {
  /** The tagged message content. */
  message: T;
  /** The numeric tag associated with the message. */
  tag: number;
}

/** Tagged message with Uint8Array format. */
export type MessageTag = GenericTag<Uint8Array>;

/** Tagged message with string format. */
export type StringMessageTag = GenericTag<string>;

/**
 * Represents a state address for cryptographic operations.
 */
export interface StateAddress {
  /** The name of the state. */
  name: string;
}

/**
 * The size of the authentication tag for ChaCha20-Poly1305.
 */
export let crypto_aead_chacha20poly1305_ABYTES: number = -1;

/**
 * The size of the authentication tag for ChaCha20-Poly1305 IETF variant.
 */
export let crypto_aead_chacha20poly1305_ietf_ABYTES: number = -1;

/**
 * The size of the authentication tag for ChaCha20-Poly1305 IETF variant (alias).
 */
export let crypto_aead_chacha20poly1305_IETF_ABYTES: number = -1;

/**
 * The size of the key for ChaCha20-Poly1305 IETF variant.
 */
export let crypto_aead_chacha20poly1305_ietf_KEYBYTES: number = -1;

/**
 * The size of the key for ChaCha20-Poly1305 IETF variant (alias).
 */
export let crypto_aead_chacha20poly1305_IETF_KEYBYTES: number = -1;

/**
 * The maximum size of a message that can be encrypted with ChaCha20-Poly1305 IETF variant.
 */
export let crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX: number = -1;

/**
 * The maximum size of a message that can be encrypted with ChaCha20-Poly1305 IETF variant (alias).
 */
export let crypto_aead_chacha20poly1305_IETF_MESSAGEBYTES_MAX: number = -1;

/**
 * The size of the public nonce for ChaCha20-Poly1305 IETF variant.
 */
export let crypto_aead_chacha20poly1305_ietf_NPUBBYTES: number = -1;

/**
 * The size of the public nonce for ChaCha20-Poly1305 IETF variant (alias).
 */
export let crypto_aead_chacha20poly1305_IETF_NPUBBYTES: number = -1;

/**
 * The size of the secret nonce for ChaCha20-Poly1305 IETF variant.
 */
export let crypto_aead_chacha20poly1305_ietf_NSECBYTES: number = -1;

/**
 * The size of the secret nonce for ChaCha20-Poly1305 IETF variant (alias).
 */
export let crypto_aead_chacha20poly1305_IETF_NSECBYTES: number = -1;

/**
 * The size of the key for ChaCha20-Poly1305.
 */
export let crypto_aead_chacha20poly1305_KEYBYTES: number = -1;

/**
 * The maximum size of a message that can be encrypted with ChaCha20-Poly1305.
 */
export let crypto_aead_chacha20poly1305_MESSAGEBYTES_MAX: number = -1;

/**
 * The size of the public nonce for ChaCha20-Poly1305.
 */
export let crypto_aead_chacha20poly1305_NPUBBYTES: number = -1;

/**
 * The size of the secret nonce for ChaCha20-Poly1305.
 */
export let crypto_aead_chacha20poly1305_NSECBYTES: number = -1;

/**
 * The size of the authentication tag for XChaCha20-Poly1305 IETF variant.
 */
export let crypto_aead_xchacha20poly1305_ietf_ABYTES: number = -1;

/**
 * The size of the authentication tag for XChaCha20-Poly1305 IETF variant (alias).
 */
export let crypto_aead_xchacha20poly1305_IETF_ABYTES: number = -1;

/**
 * The size of the key for XChaCha20-Poly1305 IETF variant.
 */
export let crypto_aead_xchacha20poly1305_ietf_KEYBYTES: number = -1;

/**
 * The size of the key for XChaCha20-Poly1305 IETF variant (alias).
 */
export let crypto_aead_xchacha20poly1305_IETF_KEYBYTES: number = -1;

/**
 * The maximum size of a message that can be encrypted with XChaCha20-Poly1305 IETF variant.
 */
export let crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX: number = -1;

/**
 * The maximum size of a message that can be encrypted with XChaCha20-Poly1305 IETF variant (alias).
 */
export let crypto_aead_xchacha20poly1305_IETF_MESSAGEBYTES_MAX: number = -1;

/**
 * The size of the public nonce for XChaCha20-Poly1305 IETF variant.
 */
export let crypto_aead_xchacha20poly1305_ietf_NPUBBYTES: number = -1;

/**
 * The size of the public nonce for XChaCha20-Poly1305 IETF variant (alias).
 */
export let crypto_aead_xchacha20poly1305_IETF_NPUBBYTES: number = -1;

/**
 * The size of the secret nonce for XChaCha20-Poly1305 IETF variant.
 */
export let crypto_aead_xchacha20poly1305_ietf_NSECBYTES: number = -1;

/**
 * The size of the secret nonce for XChaCha20-Poly1305 IETF variant (alias).
 */
export let crypto_aead_xchacha20poly1305_IETF_NSECBYTES: number = -1;

/**
 * The size of the authentication tag for AES-GCM with Aegis128L.
 */
export let crypto_aead_aegis128l_ABYTES: number = -1;

/**
 * The size of the key for AES-GCM with Aegis128L.
 */
export let crypto_aead_aegis128l_KEYBYTES: number = -1;

/**
 * The maximum size of a message that can be encrypted with AES-GCM using Aegis128L.
 */
export let crypto_aead_aegis128l_MESSAGEBYTES_MAX: number = -1;

/**
 * The size of the public nonce for AES-GCM with Aegis128L.
 */
export let crypto_aead_aegis128l_NPUBBYTES: number = -1;

/**
 * The size of the secret nonce for AES-GCM with Aegis128L.
 */
export let crypto_aead_aegis128l_NSECBYTES: number = -1;

/**
 * The size of the authentication tag for AES-GCM with Aegis256.
 */
export let crypto_aead_aegis256_ABYTES: number = -1;

/**
 * The size of the key for AES-GCM with Aegis256.
 */
export let crypto_aead_aegis256_KEYBYTES: number = -1;

/**
 * The maximum size of a message that can be encrypted with AES-GCM using Aegis256.
 */
export let crypto_aead_aegis256_MESSAGEBYTES_MAX: number = -1;

/**
 * The size of the public nonce for AES-GCM with Aegis256.
 */
export let crypto_aead_aegis256_NPUBBYTES: number = -1;

/**
 * The size of the secret nonce for AES-GCM with Aegis256.
 */
export let crypto_aead_aegis256_NSECBYTES: number = -1;

/**
 * The size of the output tag for the HMAC-based `crypto_auth` function.
 */
export let crypto_auth_BYTES: number = -1;

/**
 * The size of the key for the HMAC-based `crypto_auth` function.
 */
export let crypto_auth_KEYBYTES: number = -1;

/**
 * The size of the shared key used for precomputations in `crypto_box`.
 */
export let crypto_box_BEFORENMBYTES: number = -1;

/**
 * The size of the authentication tag produced by `crypto_box`.
 */
export let crypto_box_MACBYTES: number = -1;

/**
 * The maximum size of a message that can be encrypted using `crypto_box`.
 */
export let crypto_box_MESSAGEBYTES_MAX: number = -1;

/**
 * The size of the nonce for `crypto_box`.
 */
export let crypto_box_NONCEBYTES: number = -1;

/**
 * The size of the public key for `crypto_box`.
 */
export let crypto_box_PUBLICKEYBYTES: number = -1;

/**
 * The size of the additional overhead for `crypto_box_seal`.
 */
export let crypto_box_SEALBYTES: number = -1;

/**
 * The size of the secret key for `crypto_box`.
 */
export let crypto_box_SECRETKEYBYTES: number = -1;

/**
 * The size of the seed used to generate key pairs for `crypto_box`.
 */
export let crypto_box_SEEDBYTES: number = -1;

/**
 * The size of the output hash for `crypto_generichash`.
 */
export let crypto_generichash_BYTES: number = -1;

/**
 * The maximum size of the output hash for `crypto_generichash`.
 */
export let crypto_generichash_BYTES_MAX: number = -1;

/**
 * The minimum size of the output hash for `crypto_generichash`.
 */
export let crypto_generichash_BYTES_MIN: number = -1;

/**
 * The size of the key for `crypto_generichash`.
 */
export let crypto_generichash_KEYBYTES: number = -1;

/**
 * The maximum size of the key for `crypto_generichash`.
 */
export let crypto_generichash_KEYBYTES_MAX: number = -1;

/**
 * The minimum size of the key for `crypto_generichash`.
 */
export let crypto_generichash_KEYBYTES_MIN: number = -1;

/**
 * The size of the output hash for `crypto_hash`.
 */
export let crypto_hash_BYTES: number = -1;

/**
 * The maximum size of the derived key in `crypto_kdf`.
 */
export let crypto_kdf_BYTES_MAX: number = -1;

/**
 * The minimum size of the derived key in `crypto_kdf`.
 */
export let crypto_kdf_BYTES_MIN: number = -1;

/**
 * The size of the context for `crypto_kdf`.
 */
export let crypto_kdf_CONTEXTBYTES: number = -1;

/**
 * The size of the master key for `crypto_kdf`.
 */
export let crypto_kdf_KEYBYTES: number = -1;

/**
 * The size of the public key for `crypto_kx`.
 */
export let crypto_kx_PUBLICKEYBYTES: number = -1;

/**
 * The size of the secret key for `crypto_kx`.
 */
export let crypto_kx_SECRETKEYBYTES: number = -1;

/**
 * The size of the seed for `crypto_kx`.
 */
export let crypto_kx_SEEDBYTES: number = -1;

/**
 * The size of the session key for `crypto_kx`.
 */
export let crypto_kx_SESSIONKEYBYTES: number = -1;

/**
 * Argon2i algorithm for password hashing.
 */
export let crypto_pwhash_ALG_ARGON2I13: number = -1;

/**
 * Argon2id algorithm for password hashing.
 */
export let crypto_pwhash_ALG_ARGON2ID13: number = -1;

/**
 * Default algorithm for password hashing.
 */
export let crypto_pwhash_ALG_DEFAULT: number = -1;

/**
 * The maximum size of the derived key in `crypto_pwhash`.
 */
export let crypto_pwhash_BYTES_MAX: number = -1;

/**
 * The minimum size of the derived key in `crypto_pwhash`.
 */
export let crypto_pwhash_BYTES_MIN: number = -1;

/**
 * Memory limit for interactive password hashing.
 */
export let crypto_pwhash_MEMLIMIT_INTERACTIVE: number = -1;

/**
 * Maximum memory limit for password hashing.
 */
export let crypto_pwhash_MEMLIMIT_MAX: number = -1;

/**
 * Minimum memory limit for password hashing.
 */
export let crypto_pwhash_MEMLIMIT_MIN: number = -1;

/**
 * Memory limit for moderate password hashing.
 */
export let crypto_pwhash_MEMLIMIT_MODERATE: number = -1;

/**
 * Memory limit for sensitive password hashing.
 */
export let crypto_pwhash_MEMLIMIT_SENSITIVE: number = -1;

/**
 * Operations limit for interactive password hashing.
 */
export let crypto_pwhash_OPSLIMIT_INTERACTIVE: number = -1;

/**
 * Maximum operations limit for password hashing.
 */
export let crypto_pwhash_OPSLIMIT_MAX: number = -1;

/**
 * Minimum operations limit for password hashing.
 */
export let crypto_pwhash_OPSLIMIT_MIN: number = -1;

/**
 * Operations limit for moderate password hashing.
 */
export let crypto_pwhash_OPSLIMIT_MODERATE: number = -1;

/**
 * Operations limit for sensitive password hashing.
 */
export let crypto_pwhash_OPSLIMIT_SENSITIVE: number = -1;

/**
 * Maximum password size for `crypto_pwhash`.
 */
export let crypto_pwhash_PASSWD_MAX: number = -1;

/**
 * Minimum password size for `crypto_pwhash`.
 */
export let crypto_pwhash_PASSWD_MIN: number = -1;

/**
 * Size of the salt for `crypto_pwhash`.
 */
export let crypto_pwhash_SALTBYTES: number = -1;

/**
 * Size of the hashed password string.
 */
export let crypto_pwhash_STRBYTES: number = -1;

/**
 * Prefix for hashed password strings.
 */
export let crypto_pwhash_STRPREFIX: string = "";

/**
 * Size of the shared secret in scalar multiplication.
 */
export let crypto_scalarmult_BYTES: number = -1;

/**
 * Size of the private scalar key.
 */
export let crypto_scalarmult_SCALARBYTES: number = -1;

/**
 * Size of the key for `crypto_secretbox`.
 */
export let crypto_secretbox_KEYBYTES: number = -1;

/**
 * Size of the authentication tag for `crypto_secretbox`.
 */
export let crypto_secretbox_MACBYTES: number = -1;

/**
 * Maximum message size for `crypto_secretbox`.
 */
export let crypto_secretbox_MESSAGEBYTES_MAX: number = -1;

/**
 * Size of the nonce for `crypto_secretbox`.
 */
export let crypto_secretbox_NONCEBYTES: number = -1;

/**
 * Authentication tag size for secret streams.
 */
export let crypto_secretstream_xchacha20poly1305_ABYTES: number = -1;

/**
 * Header size for secret streams.
 */
export let crypto_secretstream_xchacha20poly1305_HEADERBYTES: number = -1;

/**
 * Key size for secret streams.
 */
export let crypto_secretstream_xchacha20poly1305_KEYBYTES: number = -1;

/**
 * Maximum message size for secret streams.
 */
export let crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX: number = -1;

/**
 * Final tag for secret streams.
 */
export let crypto_secretstream_xchacha20poly1305_TAG_FINAL: number = -1;

/**
 * Message tag for secret streams.
 */
export let crypto_secretstream_xchacha20poly1305_TAG_MESSAGE: number = -1;

/**
 * Push tag for secret streams.
 */
export let crypto_secretstream_xchacha20poly1305_TAG_PUSH: number = -1;

/**
 * Rekey tag for secret streams.
 */
export let crypto_secretstream_xchacha20poly1305_TAG_REKEY: number = -1;

/**
 * Size of the output for `crypto_shorthash`.
 */
export let crypto_shorthash_BYTES: number = -1;

/**
 * Size of the key for `crypto_shorthash`.
 */
export let crypto_shorthash_KEYBYTES: number = -1;

/**
 * Size of the signature for `crypto_sign`.
 */
export let crypto_sign_BYTES: number = -1;

/**
 * Maximum message size for `crypto_sign`.
 */
export let crypto_sign_MESSAGEBYTES_MAX: number = -1;

/**
 * Size of the public key for `crypto_sign`.
 */
export let crypto_sign_PUBLICKEYBYTES: number = -1;

/**
 * Size of the secret key for `crypto_sign`.
 */
export let crypto_sign_SECRETKEYBYTES: number = -1;

/**
 * Size of the seed for `crypto_sign`.
 */
export let crypto_sign_SEEDBYTES: number = -1;

/**
 * Sodium library major version number.
 */
export let SODIUM_LIBRARY_VERSION_MAJOR: number = -1;

/**
 * Sodium library minor version number.
 */
export let SODIUM_LIBRARY_VERSION_MINOR: number = -1;

/**
 * Sodium library version string.
 */
export let SODIUM_VERSION_STRING: string = "";

/**
 * Initializes the Sodium library and sets up constants.
 * This function must be called before using any Sodium-based cryptographic functions.
 *
 * @returns {Promise<void>} A promise that resolves when the library is ready.
 */
export async function sodium_init(): Promise<void> {
  await sodium.default.libsodium.ready;

  crypto_aead_chacha20poly1305_ABYTES =
    sodium.default.crypto_aead_chacha20poly1305_ABYTES;
  crypto_aead_chacha20poly1305_ietf_ABYTES =
    sodium.default.crypto_aead_chacha20poly1305_ietf_ABYTES;
  crypto_aead_chacha20poly1305_IETF_ABYTES =
    sodium.default.crypto_aead_chacha20poly1305_IETF_ABYTES;
  crypto_aead_chacha20poly1305_ietf_KEYBYTES =
    sodium.default.crypto_aead_chacha20poly1305_ietf_KEYBYTES;
  crypto_aead_chacha20poly1305_IETF_KEYBYTES =
    sodium.default.crypto_aead_chacha20poly1305_IETF_KEYBYTES;
  crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX =
    sodium.default.crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX;
  crypto_aead_chacha20poly1305_IETF_MESSAGEBYTES_MAX =
    sodium.default.crypto_aead_chacha20poly1305_IETF_MESSAGEBYTES_MAX;
  crypto_aead_chacha20poly1305_ietf_NPUBBYTES =
    sodium.default.crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
  crypto_aead_chacha20poly1305_IETF_NPUBBYTES =
    sodium.default.crypto_aead_chacha20poly1305_IETF_NPUBBYTES;
  crypto_aead_chacha20poly1305_ietf_NSECBYTES =
    sodium.default.crypto_aead_chacha20poly1305_ietf_NSECBYTES;
  crypto_aead_chacha20poly1305_IETF_NSECBYTES =
    sodium.default.crypto_aead_chacha20poly1305_IETF_NSECBYTES;
  crypto_aead_chacha20poly1305_KEYBYTES =
    sodium.default.crypto_aead_chacha20poly1305_KEYBYTES;
  crypto_aead_chacha20poly1305_MESSAGEBYTES_MAX =
    sodium.default.crypto_aead_chacha20poly1305_MESSAGEBYTES_MAX;
  crypto_aead_chacha20poly1305_NPUBBYTES =
    sodium.default.crypto_aead_chacha20poly1305_NPUBBYTES;
  crypto_aead_chacha20poly1305_NSECBYTES =
    sodium.default.crypto_aead_chacha20poly1305_NSECBYTES;
  crypto_aead_xchacha20poly1305_ietf_ABYTES =
    sodium.default.crypto_aead_xchacha20poly1305_ietf_ABYTES;
  crypto_aead_xchacha20poly1305_IETF_ABYTES =
    sodium.default.crypto_aead_xchacha20poly1305_IETF_ABYTES;
  crypto_aead_xchacha20poly1305_ietf_KEYBYTES =
    sodium.default.crypto_aead_xchacha20poly1305_ietf_KEYBYTES;
  crypto_aead_xchacha20poly1305_IETF_KEYBYTES =
    sodium.default.crypto_aead_xchacha20poly1305_IETF_KEYBYTES;
  crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX =
    sodium.default.crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX;
  crypto_aead_xchacha20poly1305_IETF_MESSAGEBYTES_MAX =
    sodium.default.crypto_aead_xchacha20poly1305_IETF_MESSAGEBYTES_MAX;
  crypto_aead_xchacha20poly1305_ietf_NPUBBYTES =
    sodium.default.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
  crypto_aead_xchacha20poly1305_IETF_NPUBBYTES =
    sodium.default.crypto_aead_xchacha20poly1305_IETF_NPUBBYTES;
  crypto_aead_xchacha20poly1305_ietf_NSECBYTES =
    sodium.default.crypto_aead_xchacha20poly1305_ietf_NSECBYTES;
  crypto_aead_xchacha20poly1305_IETF_NSECBYTES =
    sodium.default.crypto_aead_xchacha20poly1305_IETF_NSECBYTES;
  crypto_aead_aegis128l_ABYTES = sodium.default.crypto_aead_aegis128l_ABYTES;
  crypto_aead_aegis128l_KEYBYTES =
    sodium.default.crypto_aead_aegis128l_KEYBYTES;
  crypto_aead_aegis128l_MESSAGEBYTES_MAX =
    sodium.default.crypto_aead_aegis128l_MESSAGEBYTES_MAX;
  crypto_aead_aegis128l_NPUBBYTES =
    sodium.default.crypto_aead_aegis128l_NPUBBYTES;
  crypto_aead_aegis128l_NSECBYTES =
    sodium.default.crypto_aead_aegis128l_NSECBYTES;
  crypto_aead_aegis256_ABYTES = sodium.default.crypto_aead_aegis256_ABYTES;
  crypto_aead_aegis256_KEYBYTES = sodium.default.crypto_aead_aegis256_KEYBYTES;
  crypto_aead_aegis256_MESSAGEBYTES_MAX =
    sodium.default.crypto_aead_aegis256_MESSAGEBYTES_MAX;
  crypto_aead_aegis256_NPUBBYTES =
    sodium.default.crypto_aead_aegis256_NPUBBYTES;
  crypto_aead_aegis256_NSECBYTES =
    sodium.default.crypto_aead_aegis256_NSECBYTES;
  crypto_auth_BYTES = sodium.default.crypto_auth_BYTES;
  crypto_auth_KEYBYTES = sodium.default.crypto_auth_KEYBYTES;
  crypto_box_BEFORENMBYTES = sodium.default.crypto_box_BEFORENMBYTES;
  crypto_box_MACBYTES = sodium.default.crypto_box_MACBYTES;
  crypto_box_MESSAGEBYTES_MAX = sodium.default.crypto_box_MESSAGEBYTES_MAX;
  crypto_box_NONCEBYTES = sodium.default.crypto_box_NONCEBYTES;
  crypto_box_PUBLICKEYBYTES = sodium.default.crypto_box_PUBLICKEYBYTES;
  crypto_box_SEALBYTES = sodium.default.crypto_box_SEALBYTES;
  crypto_box_SECRETKEYBYTES = sodium.default.crypto_box_SECRETKEYBYTES;
  crypto_box_SEEDBYTES = sodium.default.crypto_box_SEEDBYTES;
  crypto_generichash_BYTES = sodium.default.crypto_generichash_BYTES;
  crypto_generichash_BYTES_MAX = sodium.default.crypto_generichash_BYTES_MAX;
  crypto_generichash_BYTES_MIN = sodium.default.crypto_generichash_BYTES_MIN;
  crypto_generichash_KEYBYTES = sodium.default.crypto_generichash_KEYBYTES;
  crypto_generichash_KEYBYTES_MAX =
    sodium.default.crypto_generichash_KEYBYTES_MAX;
  crypto_generichash_KEYBYTES_MIN =
    sodium.default.crypto_generichash_KEYBYTES_MIN;
  crypto_hash_BYTES = sodium.default.crypto_hash_BYTES;
  crypto_kdf_BYTES_MAX = sodium.default.crypto_kdf_BYTES_MAX;
  crypto_kdf_BYTES_MIN = sodium.default.crypto_kdf_BYTES_MIN;
  crypto_kdf_CONTEXTBYTES = sodium.default.crypto_kdf_CONTEXTBYTES;
  crypto_kdf_KEYBYTES = sodium.default.crypto_kdf_KEYBYTES;
  crypto_kx_PUBLICKEYBYTES = sodium.default.crypto_kx_PUBLICKEYBYTES;
  crypto_kx_SECRETKEYBYTES = sodium.default.crypto_kx_SECRETKEYBYTES;
  crypto_kx_SEEDBYTES = sodium.default.crypto_kx_SEEDBYTES;
  crypto_kx_SESSIONKEYBYTES = sodium.default.crypto_kx_SESSIONKEYBYTES;
  crypto_pwhash_ALG_ARGON2I13 = sodium.default.crypto_pwhash_ALG_ARGON2I13;
  crypto_pwhash_ALG_ARGON2ID13 = sodium.default.crypto_pwhash_ALG_ARGON2ID13;
  crypto_pwhash_ALG_DEFAULT = sodium.default.crypto_pwhash_ALG_DEFAULT;
  crypto_pwhash_BYTES_MAX = sodium.default.crypto_pwhash_BYTES_MAX;
  crypto_pwhash_BYTES_MIN = sodium.default.crypto_pwhash_BYTES_MIN;
  crypto_pwhash_MEMLIMIT_INTERACTIVE =
    sodium.default.crypto_pwhash_MEMLIMIT_INTERACTIVE;
  crypto_pwhash_MEMLIMIT_MAX = sodium.default.crypto_pwhash_MEMLIMIT_MAX;
  crypto_pwhash_MEMLIMIT_MIN = sodium.default.crypto_pwhash_MEMLIMIT_MIN;
  crypto_pwhash_MEMLIMIT_MODERATE =
    sodium.default.crypto_pwhash_MEMLIMIT_MODERATE;
  crypto_pwhash_MEMLIMIT_SENSITIVE =
    sodium.default.crypto_pwhash_MEMLIMIT_SENSITIVE;
  crypto_pwhash_OPSLIMIT_INTERACTIVE =
    sodium.default.crypto_pwhash_OPSLIMIT_INTERACTIVE;
  crypto_pwhash_OPSLIMIT_MAX = sodium.default.crypto_pwhash_OPSLIMIT_MAX;
  crypto_pwhash_OPSLIMIT_MIN = sodium.default.crypto_pwhash_OPSLIMIT_MIN;
  crypto_pwhash_OPSLIMIT_MODERATE =
    sodium.default.crypto_pwhash_OPSLIMIT_MODERATE;
  crypto_pwhash_OPSLIMIT_SENSITIVE =
    sodium.default.crypto_pwhash_OPSLIMIT_SENSITIVE;
  crypto_pwhash_PASSWD_MAX = sodium.default.crypto_pwhash_PASSWD_MAX;
  crypto_pwhash_PASSWD_MIN = sodium.default.crypto_pwhash_PASSWD_MIN;
  crypto_pwhash_SALTBYTES = sodium.default.crypto_pwhash_SALTBYTES;
  crypto_pwhash_STRBYTES = sodium.default.crypto_pwhash_STRBYTES;
  crypto_pwhash_STRPREFIX = sodium.default.crypto_pwhash_STRPREFIX;
  crypto_scalarmult_BYTES = sodium.default.crypto_scalarmult_BYTES;
  crypto_scalarmult_SCALARBYTES = sodium.default.crypto_scalarmult_SCALARBYTES;
  crypto_secretbox_KEYBYTES = sodium.default.crypto_secretbox_KEYBYTES;
  crypto_secretbox_MACBYTES = sodium.default.crypto_secretbox_MACBYTES;
  crypto_secretbox_MESSAGEBYTES_MAX =
    sodium.default.crypto_secretbox_MESSAGEBYTES_MAX;
  crypto_secretbox_NONCEBYTES = sodium.default.crypto_secretbox_NONCEBYTES;
  crypto_secretstream_xchacha20poly1305_ABYTES =
    sodium.default.crypto_secretstream_xchacha20poly1305_ABYTES;
  crypto_secretstream_xchacha20poly1305_HEADERBYTES =
    sodium.default.crypto_secretstream_xchacha20poly1305_HEADERBYTES;
  crypto_secretstream_xchacha20poly1305_KEYBYTES =
    sodium.default.crypto_secretstream_xchacha20poly1305_KEYBYTES;
  crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX =
    sodium.default.crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX;
  crypto_secretstream_xchacha20poly1305_TAG_FINAL =
    sodium.default.crypto_secretstream_xchacha20poly1305_TAG_FINAL;
  crypto_secretstream_xchacha20poly1305_TAG_MESSAGE =
    sodium.default.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;
  crypto_secretstream_xchacha20poly1305_TAG_PUSH =
    sodium.default.crypto_secretstream_xchacha20poly1305_TAG_PUSH;
  crypto_secretstream_xchacha20poly1305_TAG_REKEY =
    sodium.default.crypto_secretstream_xchacha20poly1305_TAG_REKEY;
  crypto_shorthash_BYTES = sodium.default.crypto_shorthash_BYTES;
  crypto_shorthash_KEYBYTES = sodium.default.crypto_shorthash_KEYBYTES;
  crypto_sign_BYTES = sodium.default.crypto_sign_BYTES;
  crypto_sign_MESSAGEBYTES_MAX = sodium.default.crypto_sign_MESSAGEBYTES_MAX;
  crypto_sign_PUBLICKEYBYTES = sodium.default.crypto_sign_PUBLICKEYBYTES;
  crypto_sign_SECRETKEYBYTES = sodium.default.crypto_sign_SECRETKEYBYTES;
  crypto_sign_SEEDBYTES = sodium.default.crypto_sign_SEEDBYTES;
  SODIUM_LIBRARY_VERSION_MAJOR = sodium.default.SODIUM_LIBRARY_VERSION_MAJOR;
  SODIUM_LIBRARY_VERSION_MINOR = sodium.default.SODIUM_LIBRARY_VERSION_MINOR;
  SODIUM_VERSION_STRING = sodium.default.SODIUM_VERSION_STRING;
}

// deno-lint-ignore ban-types
function execute<T>(callee: Function, ...args: unknown[]): T {
  if (callee.name in sodium.default) {
    return sodium.default[callee.name](...args);
  }

  throw new Error(`libsodium has not been loaded corretly`, {
    cause: callee.name,
  });
}

/**
 * Adds two `Uint8Array` values byte-by-byte and modifies the first array in place.
 *
 * @param {Uint8Array} a - The first array, modified in place to store the sum.
 * @param {Uint8Array} b - The second array to add.
 */
export function add(a: Uint8Array, b: Uint8Array): void {
  return execute(add, a, b);
}

/**
 * Compares two `Uint8Array` values lexicographically.
 *
 * @param {Uint8Array} b1 - The first array to compare.
 * @param {Uint8Array} b2 - The second array to compare.
 * @returns {number} - Returns 0 if equal, -1 if `b1` is less, and 1 if `b1` is greater.
 */
export function compare(b1: Uint8Array, b2: Uint8Array): number {
  return execute(compare, b1, b2);
}

/**
 * Decrypts a message encrypted using `crypto_aead_chacha20poly1305`.
 *
 * @param {string | Uint8Array | null} secret_nonce - Optional secret nonce for additional security.
 * @param {string | Uint8Array} ciphertext - The encrypted message.
 * @param {string | Uint8Array | null} additional_data - Optional additional data to authenticate.
 * @param {Uint8Array} public_nonce - The public nonce used during encryption.
 * @param {Uint8Array} key - The encryption key.
 * @param {Uint8ArrayOutputFormat | null} [outputFormat] - The desired output format (`Uint8Array`).
 * @returns {Uint8Array} - The decrypted plaintext.
 */
export function crypto_aead_chacha20poly1305_decrypt(
  secret_nonce: string | Uint8Array | null,
  ciphertext: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
/**
 * Decrypts a message encrypted using `crypto_aead_chacha20poly1305`.
 *
 * @param {string | Uint8Array | null} secret_nonce - Optional secret nonce for additional security.
 * @param {string | Uint8Array} ciphertext - The encrypted message.
 * @param {string | Uint8Array | null} additional_data - Optional additional data to authenticate.
 * @param {Uint8Array} public_nonce - The public nonce used during encryption.
 * @param {Uint8Array} key - The encryption key.
 * @param {StringOutputFormat} [outputFormat] - The desired output format (`string`).
 * @returns {string} - The decrypted plaintext.
 */
export function crypto_aead_chacha20poly1305_decrypt(
  secret_nonce: string | Uint8Array | null,
  ciphertext: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat: StringOutputFormat,
): string;
export function crypto_aead_chacha20poly1305_decrypt(
  secret_nonce: string | Uint8Array | null,
  ciphertext: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(
    crypto_aead_chacha20poly1305_decrypt,
    secret_nonce,
    ciphertext,
    additional_data,
    public_nonce,
    key,
    outputFormat,
  );
}

/**
 * Decrypts a message and validates its MAC using `crypto_aead_chacha20poly1305`.
 *
 * @param {string | Uint8Array | null} secret_nonce - Optional secret nonce for additional security.
 * @param {string | Uint8Array} ciphertext - The encrypted message.
 * @param {Uint8Array} mac - The message authentication code (MAC).
 * @param {string | Uint8Array | null} additional_data - Optional additional data to authenticate.
 * @param {Uint8Array} public_nonce - The public nonce used during encryption.
 * @param {Uint8Array} key - The encryption key.
 * @param {Uint8ArrayOutputFormat | null} [outputFormat] - The desired output format (`Uint8Array`).
 * @returns {Uint8Array} - The decrypted plaintext.
 */
export function crypto_aead_chacha20poly1305_decrypt_detached(
  secret_nonce: string | Uint8Array | null,
  ciphertext: string | Uint8Array,
  mac: Uint8Array,
  additional_data: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
/**
 * Decrypts a message and validates its MAC using `crypto_aead_chacha20poly1305`.
 *
 * @param {string | Uint8Array | null} secret_nonce - Optional secret nonce for additional security.
 * @param {string | Uint8Array} ciphertext - The encrypted message.
 * @param {Uint8Array} mac - The message authentication code (MAC).
 * @param {string | Uint8Array | null} additional_data - Optional additional data to authenticate.
 * @param {Uint8Array} public_nonce - The public nonce used during encryption.
 * @param {Uint8Array} key - The encryption key.
 * @param {Uint8ArrayOutputFormat | StringOutputFormat | null} [outputFormat] - The desired output format (`string`).
 * @returns {string} - The decrypted plaintext.
 */
export function crypto_aead_chacha20poly1305_decrypt_detached(
  secret_nonce: string | Uint8Array | null,
  ciphertext: string | Uint8Array,
  mac: Uint8Array,
  additional_data: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat: StringOutputFormat,
): string;
export function crypto_aead_chacha20poly1305_decrypt_detached(
  secret_nonce: string | Uint8Array | null,
  ciphertext: string | Uint8Array,
  mac: Uint8Array,
  additional_data: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(
    crypto_aead_chacha20poly1305_decrypt_detached,
    secret_nonce,
    ciphertext,
    mac,
    additional_data,
    public_nonce,
    key,
    outputFormat,
  );
}
/**
 * Encrypts a message using `crypto_aead_chacha20poly1305`.
 *
 * @param {string | Uint8Array} message - The plaintext message to encrypt.
 * @param {string | Uint8Array | null} additional_data - Optional additional data to authenticate.
 * @param {string | Uint8Array | null} secret_nonce - Optional secret nonce for additional security.
 * @param {Uint8Array} public_nonce - The public nonce to use during encryption.
 * @param {Uint8Array} key - The encryption key.
 * @param {Uint8ArrayOutputFormat | null} [outputFormat] - The desired output format (`Uint8Array`).
 * @returns {Uint8Array} - The encrypted ciphertext.
 */
export function crypto_aead_chacha20poly1305_encrypt(
  message: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  secret_nonce: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
/**
 * Encrypts a message using `crypto_aead_chacha20poly1305`.
 *
 * @param {string | Uint8Array} message - The plaintext message to encrypt.
 * @param {string | Uint8Array | null} additional_data - Optional additional data to authenticate.
 * @param {string | Uint8Array | null} secret_nonce - Optional secret nonce for additional security.
 * @param {Uint8Array} public_nonce - The public nonce to use during encryption.
 * @param {Uint8Array} key - The encryption key.
 * @param {Uint8ArrayOutputFormat | null} [outputFormat] - The desired output format (`string`).
 * @returns {Uint8Array} - The encrypted ciphertext.
 */
export function crypto_aead_chacha20poly1305_encrypt(
  message: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  secret_nonce: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat: StringOutputFormat,
): string;
export function crypto_aead_chacha20poly1305_encrypt(
  message: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  secret_nonce: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(
    crypto_aead_chacha20poly1305_encrypt,
    message,
    additional_data,
    secret_nonce,
    public_nonce,
    key,
    outputFormat,
  );
}
/**
 * Encrypts a message and produces a detached MAC using `crypto_aead_chacha20poly1305`.
 *
 * @param {string | Uint8Array} message - The plaintext message to encrypt.
 * @param {string | Uint8Array | null} additional_data - Optional additional data to authenticate.
 * @param {string | Uint8Array | null} secret_nonce - Optional secret nonce for additional security.
 * @param {Uint8Array} public_nonce - The public nonce to use during encryption.
 * @param {Uint8Array} key - The encryption key.
 * @param {Uint8ArrayOutputFormat | null} [outputFormat] - The desired output format (`Uint8Array`).
 * @returns {CryptoBox} - The encrypted ciphertext and MAC as a `CryptoBox`.
 */
export function crypto_aead_chacha20poly1305_encrypt_detached(
  message: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  secret_nonce: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): CryptoBox;
/**
 * Encrypts a message and produces a detached MAC using `crypto_aead_chacha20poly1305`.
 *
 * @param {string | Uint8Array} message - The plaintext message to encrypt.
 * @param {string | Uint8Array | null} additional_data - Optional additional data to authenticate.
 * @param {string | Uint8Array | null} secret_nonce - Optional secret nonce for additional security.
 * @param {Uint8Array} public_nonce - The public nonce to use during encryption.
 * @param {Uint8Array} key - The encryption key.
 * @param {StringOutputFormat} [outputFormat] - The desired output format (`string`).
 * @returns {CryptoBox | StringCryptoBox} - The encrypted ciphertext and MAC as a `StringCryptoBox`.
 */
export function crypto_aead_chacha20poly1305_encrypt_detached(
  message: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  secret_nonce: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat: StringOutputFormat,
): StringCryptoBox;
export function crypto_aead_chacha20poly1305_encrypt_detached(
  message: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  secret_nonce: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): CryptoBox | StringCryptoBox {
  return execute(
    crypto_aead_chacha20poly1305_encrypt_detached,
    message,
    additional_data,
    secret_nonce,
    public_nonce,
    key,
    outputFormat,
  );
}
/**
 * Decrypts a ciphertext using the ChaCha20-Poly1305-IETF encryption scheme, returning the result as a `Uint8Array`.
 *
 * @param {string | Uint8Array | null} secret_nonce - The secret nonce (optional).
 * @param {string | Uint8Array} ciphertext - The encrypted data to decrypt.
 * @param {string | Uint8Array | null} additional_data - Optional additional authenticated data (AAD).
 * @param {Uint8Array} public_nonce - The public nonce used during encryption.
 * @param {Uint8Array} key - The encryption key.
 * @param {Uint8ArrayOutputFormat | null} [outputFormat] - The desired output format (`Uint8Array`). Default is `Uint8Array`.
 * @returns {Uint8Array} - The decrypted plaintext as a `Uint8Array`.
 */
export function crypto_aead_chacha20poly1305_ietf_decrypt(
  secret_nonce: string | Uint8Array | null,
  ciphertext: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
/**
 * Decrypts a ciphertext using the ChaCha20-Poly1305-IETF encryption scheme, returning the result as a `string`.
 *
 * @param {string | Uint8Array | null} secret_nonce - The secret nonce (optional).
 * @param {string | Uint8Array} ciphertext - The encrypted data to decrypt.
 * @param {string | Uint8Array | null} additional_data - Optional additional authenticated data (AAD).
 * @param {Uint8Array} public_nonce - The public nonce used during encryption.
 * @param {Uint8Array} key - The encryption key.
 * @param {StringOutputFormat} outputFormat - The desired output format (`string`).
 * @returns {string} - The decrypted plaintext as a `string`.
 */
export function crypto_aead_chacha20poly1305_ietf_decrypt(
  secret_nonce: string | Uint8Array | null,
  ciphertext: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat: StringOutputFormat,
): string;
export function crypto_aead_chacha20poly1305_ietf_decrypt(
  secret_nonce: string | Uint8Array | null,
  ciphertext: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(
    crypto_aead_chacha20poly1305_ietf_decrypt,
    secret_nonce,
    ciphertext,
    additional_data,
    public_nonce,
    key,
    outputFormat,
  );
}

/**
 * Decrypts a detached ciphertext using the ChaCha20-Poly1305-IETF encryption scheme, returning the result as a `Uint8Array`.
 *
 * @param {string | Uint8Array | null} secret_nonce - The secret nonce (optional).
 * @param {string | Uint8Array} ciphertext - The encrypted data to decrypt.
 * @param {Uint8Array} mac - The detached MAC tag for authentication.
 * @param {string | Uint8Array | null} additional_data - Optional additional authenticated data (AAD).
 * @param {Uint8Array} public_nonce - The public nonce used during encryption.
 * @param {Uint8Array} key - The encryption key.
 * @param {Uint8ArrayOutputFormat | null} [outputFormat] - The desired output format (`Uint8Array`). Default is `Uint8Array`.
 * @returns {Uint8Array} - The decrypted plaintext as a `Uint8Array`.
 */
export function crypto_aead_chacha20poly1305_ietf_decrypt_detached(
  secret_nonce: string | Uint8Array | null,
  ciphertext: string | Uint8Array,
  mac: Uint8Array,
  additional_data: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
/**
 * Decrypts a detached ciphertext using the ChaCha20-Poly1305-IETF encryption scheme, returning the result as a `string`.
 *
 * @param {string | Uint8Array | null} secret_nonce - The secret nonce (optional).
 * @param {string | Uint8Array} ciphertext - The encrypted data to decrypt.
 * @param {Uint8Array} mac - The detached MAC tag for authentication.
 * @param {string | Uint8Array | null} additional_data - Optional additional authenticated data (AAD).
 * @param {Uint8Array} public_nonce - The public nonce used during encryption.
 * @param {Uint8Array} key - The encryption key.
 * @param {StringOutputFormat} outputFormat - The desired output format (`string`).
 * @returns {string} - The decrypted plaintext as a `string`.
 */
export function crypto_aead_chacha20poly1305_ietf_decrypt_detached(
  secret_nonce: string | Uint8Array | null,
  ciphertext: string | Uint8Array,
  mac: Uint8Array,
  additional_data: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat: StringOutputFormat,
): string;
export function crypto_aead_chacha20poly1305_ietf_decrypt_detached(
  secret_nonce: string | Uint8Array | null,
  ciphertext: string | Uint8Array,
  mac: Uint8Array,
  additional_data: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(
    crypto_aead_chacha20poly1305_ietf_decrypt_detached,
    secret_nonce,
    ciphertext,
    mac,
    additional_data,
    public_nonce,
    key,
    outputFormat,
  );
}

/**
 * Encrypts a message using the ChaCha20-Poly1305-IETF encryption scheme, returning the ciphertext as a `Uint8Array`.
 *
 * @param {string | Uint8Array} message - The plaintext message to encrypt.
 * @param {string | Uint8Array | null} additional_data - Optional additional authenticated data (AAD).
 * @param {string | Uint8Array | null} secret_nonce - The secret nonce (optional).
 * @param {Uint8Array} public_nonce - The public nonce used during encryption.
 * @param {Uint8Array} key - The encryption key.
 * @param {Uint8ArrayOutputFormat | null} [outputFormat] - The desired output format (`Uint8Array`). Default is `Uint8Array`.
 * @returns {Uint8Array} - The encrypted ciphertext as a `Uint8Array`.
 */
export function crypto_aead_chacha20poly1305_ietf_encrypt(
  message: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  secret_nonce: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
/**
 * Encrypts a message using the ChaCha20-Poly1305-IETF encryption scheme, returning the ciphertext as a `string`.
 *
 * @param {string | Uint8Array} message - The plaintext message to encrypt.
 * @param {string | Uint8Array | null} additional_data - Optional additional authenticated data (AAD).
 * @param {string | Uint8Array | null} secret_nonce - The secret nonce (optional).
 * @param {Uint8Array} public_nonce - The public nonce used during encryption.
 * @param {Uint8Array} key - The encryption key.
 * @param {StringOutputFormat} outputFormat - The desired output format (`string`).
 * @returns {string} - The encrypted ciphertext as a `string`.
 */
export function crypto_aead_chacha20poly1305_ietf_encrypt(
  message: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  secret_nonce: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat: StringOutputFormat,
): string;
export function crypto_aead_chacha20poly1305_ietf_encrypt(
  message: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  secret_nonce: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(
    crypto_aead_chacha20poly1305_ietf_encrypt,
    message,
    additional_data,
    secret_nonce,
    public_nonce,
    key,
    outputFormat,
  );
}

/**
 * Encrypts a message using the ChaCha20-Poly1305-IETF encryption scheme, returning the ciphertext and detached MAC as a `CryptoBox` object.
 *
 * @param {string | Uint8Array} message - The plaintext message to encrypt.
 * @param {string | Uint8Array | null} additional_data - Optional additional authenticated data (AAD).
 * @param {string | Uint8Array | null} secret_nonce - The secret nonce (optional).
 * @param {Uint8Array} public_nonce - The public nonce used during encryption.
 * @param {Uint8Array} key - The encryption key.
 * @param {Uint8ArrayOutputFormat | null} [outputFormat] - The desired output format (`Uint8Array`). Default is `Uint8Array`.
 * @returns {CryptoBox} - An object containing the encrypted ciphertext and detached MAC.
 */
export function crypto_aead_chacha20poly1305_ietf_encrypt_detached(
  message: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  secret_nonce: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): CryptoBox;
/**
 * Encrypts a message using the ChaCha20-Poly1305-IETF encryption scheme, returning the ciphertext and detached MAC as a `StringCryptoBox` object.
 *
 * @param {string | Uint8Array} message - The plaintext message to encrypt.
 * @param {string | Uint8Array | null} additional_data - Optional additional authenticated data (AAD).
 * @param {string | Uint8Array | null} secret_nonce - The secret nonce (optional).
 * @param {Uint8Array} public_nonce - The public nonce used during encryption.
 * @param {Uint8Array} key - The encryption key.
 * @param {StringOutputFormat} outputFormat - The desired output format (`string`).
 * @returns {StringCryptoBox} - An object containing the encrypted ciphertext and detached MAC as `string`.
 */
export function crypto_aead_chacha20poly1305_ietf_encrypt_detached(
  message: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  secret_nonce: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat: StringOutputFormat,
): StringCryptoBox;
export function crypto_aead_chacha20poly1305_ietf_encrypt_detached(
  message: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  secret_nonce: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): CryptoBox | StringCryptoBox {
  return execute(
    crypto_aead_chacha20poly1305_ietf_encrypt_detached,
    message,
    additional_data,
    secret_nonce,
    public_nonce,
    key,
    outputFormat,
  );
}

/**
 * Generates a random key for use with `crypto_aead_chacha20poly1305_ietf` encryption, returning the key as a `Uint8Array`.
 *
 * @param {Uint8ArrayOutputFormat | null} [outputFormat] - The desired output format (`Uint8Array`). Default is `Uint8Array`.
 * @returns {Uint8Array} - The generated key as a `Uint8Array`.
 */
export function crypto_aead_chacha20poly1305_ietf_keygen(
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
/**
 * Generates a random key for use with `crypto_aead_chacha20poly1305_ietf` encryption, returning the key as a `string`.
 *
 * @param {StringOutputFormat} outputFormat - The desired output format (`string`).
 * @returns {string} - The generated key as a `string`.
 */
export function crypto_aead_chacha20poly1305_ietf_keygen(
  outputFormat: StringOutputFormat,
): string;
export function crypto_aead_chacha20poly1305_ietf_keygen(
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(crypto_aead_chacha20poly1305_ietf_keygen, outputFormat);
}

/**
 * Generates a random key for use with `crypto_aead_chacha20poly1305` encryption, returning the key as a `Uint8Array`.
 *
 * @param {Uint8ArrayOutputFormat | null} [outputFormat] - The desired output format (`Uint8Array`). Default is `Uint8Array`.
 * @returns {Uint8Array} - The generated key as a `Uint8Array`.
 */
export function crypto_aead_chacha20poly1305_keygen(
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
/**
 * Generates a random key for use with `crypto_aead_chacha20poly1305` encryption, returning the key as a `string`.
 *
 * @param {StringOutputFormat} outputFormat - The desired output format (`string`).
 * @returns {string} - The generated key as a `string`.
 */
export function crypto_aead_chacha20poly1305_keygen(
  outputFormat: StringOutputFormat,
): string;
export function crypto_aead_chacha20poly1305_keygen(
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(crypto_aead_chacha20poly1305_keygen, outputFormat);
}

/**
 * Decrypts a ciphertext using the XChaCha20-Poly1305-IETF encryption scheme, returning the result as a `Uint8Array`.
 *
 * @param {string | Uint8Array | null} secret_nonce - The optional secret nonce.
 * @param {string | Uint8Array} ciphertext - The encrypted data to decrypt.
 * @param {string | Uint8Array | null} additional_data - Optional additional authenticated data (AAD).
 * @param {Uint8Array} public_nonce - The public nonce used during encryption.
 * @param {Uint8Array} key - The encryption key.
 * @param {Uint8ArrayOutputFormat | null} outputFormat - The desired output format (`Uint8Array`).
 * @returns {Uint8Array} - The decrypted plaintext as a `Uint8Array`.
 */
export function crypto_aead_xchacha20poly1305_ietf_decrypt(
  secret_nonce: string | Uint8Array | null,
  ciphertext: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
/**
 * Decrypts a ciphertext using the XChaCha20-Poly1305-IETF encryption scheme, returning the result as a `string`.
 *
 * @param {string | Uint8Array | null} secret_nonce - The optional secret nonce.
 * @param {string | Uint8Array} ciphertext - The encrypted data to decrypt.
 * @param {string | Uint8Array | null} additional_data - Optional additional authenticated data (AAD).
 * @param {Uint8Array} public_nonce - The public nonce used during encryption.
 * @param {Uint8Array} key - The encryption key.
 * @param {StringOutputFormat} outputFormat - The desired output format (`string`).
 * @returns {string} - The decrypted plaintext as a `string`.
 */
export function crypto_aead_xchacha20poly1305_ietf_decrypt(
  secret_nonce: string | Uint8Array | null,
  ciphertext: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat: StringOutputFormat,
): string;
export function crypto_aead_xchacha20poly1305_ietf_decrypt(
  secret_nonce: string | Uint8Array | null,
  ciphertext: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    secret_nonce,
    ciphertext,
    additional_data,
    public_nonce,
    key,
    outputFormat,
  );
}

/**
 * Decrypts a detached ciphertext using the XChaCha20-Poly1305-IETF encryption scheme, returning the result as a `Uint8Array`.
 *
 * @param {string | Uint8Array | null} secret_nonce - The optional secret nonce.
 * @param {string | Uint8Array} ciphertext - The encrypted data to decrypt.
 * @param {Uint8Array} mac - The detached MAC tag for authentication.
 * @param {string | Uint8Array | null} additional_data - Optional additional authenticated data (AAD).
 * @param {Uint8Array} public_nonce - The public nonce used during encryption.
 * @param {Uint8Array} key - The encryption key.
 * @param {Uint8ArrayOutputFormat | null} [outputFormat] - The desired output format (`Uint8Array`). Default is `Uint8Array`.
 * @returns {Uint8Array} - The decrypted plaintext as a `Uint8Array`.
 */
export function crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
  secret_nonce: string | Uint8Array | null,
  ciphertext: string | Uint8Array,
  mac: Uint8Array,
  additional_data: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
/**
 * Decrypts a detached ciphertext using the XChaCha20-Poly1305-IETF encryption scheme, returning the result as a `string`.
 *
 * @param {string | Uint8Array | null} secret_nonce - The optional secret nonce.
 * @param {string | Uint8Array} ciphertext - The encrypted data to decrypt.
 * @param {Uint8Array} mac - The detached MAC tag for authentication.
 * @param {string | Uint8Array | null} additional_data - Optional additional authenticated data (AAD).
 * @param {Uint8Array} public_nonce - The public nonce used during encryption.
 * @param {Uint8Array} key - The encryption key.
 * @param {StringOutputFormat} outputFormat - The desired output format (`string`).
 * @returns {string} - The decrypted plaintext as a `string`.
 */
export function crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
  secret_nonce: string | Uint8Array | null,
  ciphertext: string | Uint8Array,
  mac: Uint8Array,
  additional_data: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat: StringOutputFormat,
): string;
export function crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
  secret_nonce: string | Uint8Array | null,
  ciphertext: string | Uint8Array,
  mac: Uint8Array,
  additional_data: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(
    crypto_aead_xchacha20poly1305_ietf_decrypt_detached,
    secret_nonce,
    ciphertext,
    mac,
    additional_data,
    public_nonce,
    key,
    outputFormat,
  );
}

/**
 * Encrypts a message using the XChaCha20-Poly1305-IETF encryption scheme, returning the ciphertext as a `Uint8Array`.
 *
 * @param {string | Uint8Array} message - The plaintext message to encrypt.
 * @param {string | Uint8Array | null} additional_data - Optional additional authenticated data (AAD).
 * @param {string | Uint8Array | null} secret_nonce - The optional secret nonce.
 * @param {Uint8Array} public_nonce - The public nonce used during encryption.
 * @param {Uint8Array} key - The encryption key.
 * @param {Uint8ArrayOutputFormat | null} [outputFormat] - The desired output format (`Uint8Array`). Default is `Uint8Array`.
 * @returns {Uint8Array} - The encrypted ciphertext as a `Uint8Array`.
 */
export function crypto_aead_xchacha20poly1305_ietf_encrypt(
  message: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  secret_nonce: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
/**
 * Encrypts a message using the XChaCha20-Poly1305-IETF encryption scheme, returning the ciphertext as a `string`.
 *
 * @param {string | Uint8Array} message - The plaintext message to encrypt.
 * @param {string | Uint8Array | null} additional_data - Optional additional authenticated data (AAD).
 * @param {string | Uint8Array | null} secret_nonce - The optional secret nonce.
 * @param {Uint8Array} public_nonce - The public nonce used during encryption.
 * @param {Uint8Array} key - The encryption key.
 * @param {StringOutputFormat} outputFormat - The desired output format (`string`).
 * @returns {string} - The encrypted ciphertext as a `string`.
 */
export function crypto_aead_xchacha20poly1305_ietf_encrypt(
  message: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  secret_nonce: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat: StringOutputFormat,
): string;
export function crypto_aead_xchacha20poly1305_ietf_encrypt(
  message: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  secret_nonce: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(
    crypto_aead_xchacha20poly1305_ietf_encrypt,
    message,
    additional_data,
    secret_nonce,
    public_nonce,
    key,
    outputFormat,
  );
}

/**
 * Encrypts a message using the XChaCha20-Poly1305-IETF encryption scheme, returning the ciphertext and detached MAC as a `CryptoBox`.
 *
 * @param {string | Uint8Array} message - The plaintext message to encrypt.
 * @param {string | Uint8Array | null} additional_data - Optional additional authenticated data (AAD).
 * @param {string | Uint8Array | null} secret_nonce - The optional secret nonce.
 * @param {Uint8Array} public_nonce - The public nonce used during encryption.
 * @param {Uint8Array} key - The encryption key.
 * @param {Uint8ArrayOutputFormat | null} [outputFormat] - The desired output format (`Uint8Array`). Default is `Uint8Array`.
 * @returns {CryptoBox} - An object containing the encrypted ciphertext and detached MAC.
 */
export function crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
  message: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  secret_nonce: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): CryptoBox;
/**
 * Encrypts a message using the XChaCha20-Poly1305-IETF encryption scheme, returning the ciphertext and detached MAC as a `StringCryptoBox`.
 *
 * @param {string | Uint8Array} message - The plaintext message to encrypt.
 * @param {string | Uint8Array | null} additional_data - Optional additional authenticated data (AAD).
 * @param {string | Uint8Array | null} secret_nonce - The optional secret nonce.
 * @param {Uint8Array} public_nonce - The public nonce used during encryption.
 * @param {Uint8Array} key - The encryption key.
 * @param {StringOutputFormat} outputFormat - The desired output format (`string`).
 * @returns {StringCryptoBox} - An object containing the encrypted ciphertext and detached MAC as `string`.
 */
export function crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
  message: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  secret_nonce: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat: StringOutputFormat,
): StringCryptoBox;
export function crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
  message: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  secret_nonce: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): CryptoBox | StringCryptoBox {
  return execute(
    crypto_aead_xchacha20poly1305_ietf_encrypt_detached,
    message,
    additional_data,
    secret_nonce,
    public_nonce,
    key,
    outputFormat,
  );
}

/**
 * Generates a key for use with XChaCha20-Poly1305-IETF encryption.
 *
 * @param {Uint8ArrayOutputFormat | null} [outputFormat=null] - The desired output format of the key. Defaults to `Uint8Array`.
 * @returns {Uint8Array} The generated key in `Uint8Array` format.
 */
export function crypto_aead_xchacha20poly1305_ietf_keygen(
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
/**
 * Generates a key for use with XChaCha20-Poly1305-IETF encryption.
 *
 * @param {StringOutputFormat} outputFormat - The desired output format of the key as a string.
 * @returns {string} The generated key as a string.
 */
export function crypto_aead_xchacha20poly1305_ietf_keygen(
  outputFormat: StringOutputFormat,
): string;
export function crypto_aead_xchacha20poly1305_ietf_keygen(
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(crypto_aead_xchacha20poly1305_ietf_keygen, outputFormat);
}

/**
 * Decrypts ciphertext encrypted using AEGIS-128L.
 *
 * @param {string | Uint8Array | null} secret_nonce - An optional secret nonce for decryption.
 * @param {string | Uint8Array} ciphertext - The encrypted ciphertext to decrypt.
 * @param {string | Uint8Array | null} additional_data - Optional additional authenticated data.
 * @param {Uint8Array} public_nonce - The public nonce used for encryption.
 * @param {Uint8Array} key - The encryption key.
 * @param {Uint8ArrayOutputFormat | null} [outputFormat=null] - The desired output format. Defaults to `Uint8Array`.
 * @returns {Uint8Array} The decrypted message in `Uint8Array` format.
 */
export function crypto_aead_aegis128l_decrypt(
  secret_nonce: string | Uint8Array | null,
  ciphertext: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
/**
 * Decrypts ciphertext encrypted using AEGIS-128L.
 *
 * @param {string | Uint8Array | null} secret_nonce - An optional secret nonce for decryption.
 * @param {string | Uint8Array} ciphertext - The encrypted ciphertext to decrypt.
 * @param {string | Uint8Array | null} additional_data - Optional additional authenticated data.
 * @param {Uint8Array} public_nonce - The public nonce used for encryption.
 * @param {Uint8Array} key - The encryption key.
 * @param {StringOutputFormat} outputFormat - The desired output format as a string.
 * @returns {string} The decrypted message as a string.
 */
export function crypto_aead_aegis128l_decrypt(
  secret_nonce: string | Uint8Array | null,
  ciphertext: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat: StringOutputFormat,
): string;
export function crypto_aead_aegis128l_decrypt(
  secret_nonce: string | Uint8Array | null,
  ciphertext: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(
    crypto_aead_aegis128l_decrypt,
    secret_nonce,
    ciphertext,
    additional_data,
    public_nonce,
    key,
    outputFormat,
  );
}

/**
 * Decrypts detached ciphertext and verifies its integrity using AEGIS-128L.
 *
 * @param {string | Uint8Array | null} secret_nonce - An optional secret nonce for decryption.
 * @param {string | Uint8Array} ciphertext - The detached encrypted ciphertext to decrypt.
 * @param {Uint8Array} mac - The authentication tag for verification.
 * @param {string | Uint8Array | null} additional_data - Optional additional authenticated data.
 * @param {Uint8Array} public_nonce - The public nonce used for encryption.
 * @param {Uint8Array} key - The encryption key.
 * @param {Uint8ArrayOutputFormat | null} [outputFormat=null] - The desired output format. Defaults to `Uint8Array`.
 * @returns {Uint8Array} The decrypted message in `Uint8Array` format.
 */
export function crypto_aead_aegis128l_decrypt_detached(
  secret_nonce: string | Uint8Array | null,
  ciphertext: string | Uint8Array,
  mac: Uint8Array,
  additional_data: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
/**
 * Decrypts detached ciphertext and verifies its integrity using AEGIS-128L.
 *
 * @param {string | Uint8Array | null} secret_nonce - An optional secret nonce for decryption.
 * @param {string | Uint8Array} ciphertext - The detached encrypted ciphertext to decrypt.
 * @param {Uint8Array} mac - The authentication tag for verification.
 * @param {string | Uint8Array | null} additional_data - Optional additional authenticated data.
 * @param {Uint8Array} public_nonce - The public nonce used for encryption.
 * @param {Uint8Array} key - The encryption key.
 * @param {StringOutputFormat} outputFormat - The desired output format as a string.
 * @returns {string} The decrypted message as a string.
 */
export function crypto_aead_aegis128l_decrypt_detached(
  secret_nonce: string | Uint8Array | null,
  ciphertext: string | Uint8Array,
  mac: Uint8Array,
  additional_data: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat: StringOutputFormat,
): string;
export function crypto_aead_aegis128l_decrypt_detached(
  secret_nonce: string | Uint8Array | null,
  ciphertext: string | Uint8Array,
  mac: Uint8Array,
  additional_data: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(
    crypto_aead_aegis128l_decrypt_detached,
    secret_nonce,
    ciphertext,
    mac,
    additional_data,
    public_nonce,
    key,
    outputFormat,
  );
}

/**
 * Encrypts a message using AEGIS-128L.
 *
 * @param {string | Uint8Array} message - The plaintext message to encrypt.
 * @param {string | Uint8Array | null} additional_data - Optional additional authenticated data.
 * @param {string | Uint8Array | null} secret_nonce - An optional secret nonce for encryption.
 * @param {Uint8Array} public_nonce - The public nonce to use for encryption.
 * @param {Uint8Array} key - The encryption key.
 * @param {Uint8ArrayOutputFormat | null} [outputFormat=null] - The desired output format. Defaults to `Uint8Array`.
 * @returns {Uint8Array} The encrypted ciphertext in `Uint8Array` format.
 */
export function crypto_aead_aegis128l_encrypt(
  message: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  secret_nonce: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
/**
 * Encrypts a message using AEGIS-128L.
 *
 * @param {string | Uint8Array} message - The plaintext message to encrypt.
 * @param {string | Uint8Array | null} additional_data - Optional additional authenticated data.
 * @param {string | Uint8Array | null} secret_nonce - An optional secret nonce for encryption.
 * @param {Uint8Array} public_nonce - The public nonce to use for encryption.
 * @param {Uint8Array} key - The encryption key.
 * @param {StringOutputFormat} outputFormat - The desired output format as a string.
 * @returns {string} The encrypted ciphertext as a string.
 */
export function crypto_aead_aegis128l_encrypt(
  message: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  secret_nonce: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat: StringOutputFormat,
): string;
export function crypto_aead_aegis128l_encrypt(
  message: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  secret_nonce: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(
    crypto_aead_aegis128l_encrypt,
    message,
    additional_data,
    secret_nonce,
    public_nonce,
    key,
    outputFormat,
  );
}

/**
 * Encrypts a message using AEGIS-128L and returns a detached ciphertext with an authentication tag.
 *
 * @param {string | Uint8Array} message - The plaintext message to encrypt.
 * @param {string | Uint8Array | null} additional_data - Optional additional authenticated data.
 * @param {string | Uint8Array | null} secret_nonce - An optional secret nonce for encryption.
 * @param {Uint8Array} public_nonce - The public nonce to use for encryption.
 * @param {Uint8Array} key - The encryption key.
 * @param {Uint8ArrayOutputFormat | null} [outputFormat=null] - The desired output format. Defaults to `CryptoBox`.
 * @returns {CryptoBox} The encrypted message and authentication tag in a `CryptoBox` format.
 */
export function crypto_aead_aegis128l_encrypt_detached(
  message: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  secret_nonce: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): CryptoBox;
/**
 * Encrypts a message using AEGIS-128L and returns a detached ciphertext with an authentication tag.
 *
 * @param {string | Uint8Array} message - The plaintext message to encrypt.
 * @param {string | Uint8Array | null} additional_data - Optional additional authenticated data.
 * @param {string | Uint8Array | null} secret_nonce - An optional secret nonce for encryption.
 * @param {Uint8Array} public_nonce - The public nonce to use for encryption.
 * @param {Uint8Array} key - The encryption key.
 * @param {StringOutputFormat} outputFormat - The desired output format as a string.
 * @returns {StringCryptoBox} The encrypted message and authentication tag as a string in `StringCryptoBox` format.
 */
export function crypto_aead_aegis128l_encrypt_detached(
  message: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  secret_nonce: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat: StringOutputFormat,
): StringCryptoBox;
export function crypto_aead_aegis128l_encrypt_detached(
  message: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  secret_nonce: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): CryptoBox | StringCryptoBox {
  return execute(
    crypto_aead_aegis128l_encrypt_detached,
    message,
    additional_data,
    secret_nonce,
    public_nonce,
    key,
    outputFormat,
  );
}

/**
 * Generates a key for use with AEGIS-128L encryption.
 *
 * @param {Uint8ArrayOutputFormat | null} [outputFormat=null] - The desired output format of the key. Defaults to `Uint8Array`.
 * @returns {Uint8Array} The generated key in `Uint8Array` format.
 */
export function crypto_aead_aegis128l_keygen(
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
/**
 * Generates a key for use with AEGIS-128L encryption.
 *
 * @param {StringOutputFormat} outputFormat - The desired output format of the key as a string.
 * @returns {string} The generated key as a string.
 */
export function crypto_aead_aegis128l_keygen(
  outputFormat: StringOutputFormat,
): string;
export function crypto_aead_aegis128l_keygen(
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(crypto_aead_aegis128l_keygen, outputFormat);
}

/**
 * Decrypts ciphertext encrypted using AEGIS-256.
 *
 * @param {string | Uint8Array | null} secret_nonce - An optional secret nonce for decryption.
 * @param {string | Uint8Array} ciphertext - The encrypted ciphertext to decrypt.
 * @param {string | Uint8Array | null} additional_data - Optional additional authenticated data.
 * @param {Uint8Array} public_nonce - The public nonce used for encryption.
 * @param {Uint8Array} key - The encryption key.
 * @param {Uint8ArrayOutputFormat | null} [outputFormat=null] - The desired output format. Defaults to `Uint8Array`.
 * @returns {Uint8Array} The decrypted message in `Uint8Array` format.
 */
export function crypto_aead_aegis256_decrypt(
  secret_nonce: string | Uint8Array | null,
  ciphertext: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
/**
 * Decrypts ciphertext encrypted using AEGIS-256.
 *
 * @param {string | Uint8Array | null} secret_nonce - An optional secret nonce for decryption.
 * @param {string | Uint8Array} ciphertext - The encrypted ciphertext to decrypt.
 * @param {string | Uint8Array | null} additional_data - Optional additional authenticated data.
 * @param {Uint8Array} public_nonce - The public nonce used for encryption.
 * @param {Uint8Array} key - The encryption key.
 * @param {StringOutputFormat} outputFormat - The desired output format as a string.
 * @returns {string} The decrypted message as a string.
 */
export function crypto_aead_aegis256_decrypt(
  secret_nonce: string | Uint8Array | null,
  ciphertext: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat: StringOutputFormat,
): string;
export function crypto_aead_aegis256_decrypt(
  secret_nonce: string | Uint8Array | null,
  ciphertext: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(
    crypto_aead_aegis256_decrypt,
    secret_nonce,
    ciphertext,
    additional_data,
    public_nonce,
    key,
    outputFormat,
  );
}

/**
 * Decrypts detached ciphertext and verifies its integrity using AEGIS-256.
 *
 * @param {string | Uint8Array | null} secret_nonce - An optional secret nonce for decryption.
 * @param {string | Uint8Array} ciphertext - The detached encrypted ciphertext to decrypt.
 * @param {Uint8Array} mac - The authentication tag for verification.
 * @param {string | Uint8Array | null} additional_data - Optional additional authenticated data.
 * @param {Uint8Array} public_nonce - The public nonce used for encryption.
 * @param {Uint8Array} key - The encryption key.
 * @param {Uint8ArrayOutputFormat | null} [outputFormat=null] - The desired output format. Defaults to `Uint8Array`.
 * @returns {Uint8Array} The decrypted message in `Uint8Array` format.
 */
export function crypto_aead_aegis256_decrypt_detached(
  secret_nonce: string | Uint8Array | null,
  ciphertext: string | Uint8Array,
  mac: Uint8Array,
  additional_data: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
/**
 * Decrypts detached ciphertext and verifies its integrity using AEGIS-256.
 *
 * @param {string | Uint8Array | null} secret_nonce - An optional secret nonce for decryption.
 * @param {string | Uint8Array} ciphertext - The detached encrypted ciphertext to decrypt.
 * @param {Uint8Array} mac - The authentication tag for verification.
 * @param {string | Uint8Array | null} additional_data - Optional additional authenticated data.
 * @param {Uint8Array} public_nonce - The public nonce used for encryption.
 * @param {Uint8Array} key - The encryption key.
 * @param {StringOutputFormat} outputFormat - The desired output format as a string.
 * @returns {string} The decrypted message as a string.
 */
export function crypto_aead_aegis256_decrypt_detached(
  secret_nonce: string | Uint8Array | null,
  ciphertext: string | Uint8Array,
  mac: Uint8Array,
  additional_data: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat: StringOutputFormat,
): string;
export function crypto_aead_aegis256_decrypt_detached(
  secret_nonce: string | Uint8Array | null,
  ciphertext: string | Uint8Array,
  mac: Uint8Array,
  additional_data: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(
    crypto_aead_aegis256_decrypt_detached,
    secret_nonce,
    ciphertext,
    mac,
    additional_data,
    public_nonce,
    key,
    outputFormat,
  );
}

/**
 * Encrypts a message using AEGIS-256.
 *
 * @param {string | Uint8Array} message - The plaintext message to encrypt.
 * @param {string | Uint8Array | null} additional_data - Optional additional authenticated data.
 * @param {string | Uint8Array | null} secret_nonce - An optional secret nonce for encryption.
 * @param {Uint8Array} public_nonce - The public nonce to use for encryption.
 * @param {Uint8Array} key - The encryption key.
 * @param {Uint8ArrayOutputFormat | null} [outputFormat=null] - The desired output format. Defaults to `Uint8Array`.
 * @returns {Uint8Array} The encrypted ciphertext in `Uint8Array` format.
 */
export function crypto_aead_aegis256_encrypt(
  message: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  secret_nonce: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
/**
 * Encrypts a message using AEGIS-256.
 *
 * @param {string | Uint8Array} message - The plaintext message to encrypt.
 * @param {string | Uint8Array | null} additional_data - Optional additional authenticated data.
 * @param {string | Uint8Array | null} secret_nonce - An optional secret nonce for encryption.
 * @param {Uint8Array} public_nonce - The public nonce to use for encryption.
 * @param {Uint8Array} key - The encryption key.
 * @param {StringOutputFormat} outputFormat - The desired output format as a string.
 * @returns {string} The encrypted ciphertext as a string.
 */
export function crypto_aead_aegis256_encrypt(
  message: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  secret_nonce: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat: StringOutputFormat,
): string;
export function crypto_aead_aegis256_encrypt(
  message: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  secret_nonce: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(
    crypto_aead_aegis256_encrypt,
    message,
    additional_data,
    secret_nonce,
    public_nonce,
    key,
    outputFormat,
  );
}

/**
 * Encrypts a message using AEGIS-256 and returns a detached ciphertext with an authentication tag.
 *
 * @param {string | Uint8Array} message - The plaintext message to encrypt.
 * @param {string | Uint8Array | null} additional_data - Optional additional authenticated data.
 * @param {string | Uint8Array | null} secret_nonce - An optional secret nonce for encryption.
 * @param {Uint8Array} public_nonce - The public nonce to use for encryption.
 * @param {Uint8Array} key - The encryption key.
 * @param {Uint8ArrayOutputFormat | null} [outputFormat=null] - The desired output format. Defaults to `CryptoBox`.
 * @returns {CryptoBox} The encrypted message and authentication tag in `CryptoBox` format.
 */
export function crypto_aead_aegis256_encrypt_detached(
  message: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  secret_nonce: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): CryptoBox;
/**
 * Encrypts a message using AEGIS-256 and returns a detached ciphertext with an authentication tag.
 *
 * @param {string | Uint8Array} message - The plaintext message to encrypt.
 * @param {string | Uint8Array | null} additional_data - Optional additional authenticated data.
 * @param {string | Uint8Array | null} secret_nonce - An optional secret nonce for encryption.
 * @param {Uint8Array} public_nonce - The public nonce to use for encryption.
 * @param {Uint8Array} key - The encryption key.
 * @param {StringOutputFormat} outputFormat - The desired output format as a string.
 * @returns {StringCryptoBox} The encrypted message and authentication tag as a string in `StringCryptoBox` format.
 */
export function crypto_aead_aegis256_encrypt_detached(
  message: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  secret_nonce: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat: StringOutputFormat,
): StringCryptoBox;
export function crypto_aead_aegis256_encrypt_detached(
  message: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  secret_nonce: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): CryptoBox | StringCryptoBox {
  return execute(
    crypto_aead_aegis256_encrypt_detached,
    message,
    additional_data,
    secret_nonce,
    public_nonce,
    key,
    outputFormat,
  );
}

/**
 * Generates a key for use with AEGIS-256 encryption.
 *
 * @param {Uint8ArrayOutputFormat | null} [outputFormat=null] - The desired output format of the key. Defaults to `Uint8Array`.
 * @returns {Uint8Array} The generated key in `Uint8Array` format.
 */
export function crypto_aead_aegis256_keygen(
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;

/**
 * Generates a key for use with AEGIS-256 encryption.
 *
 * @param {StringOutputFormat} outputFormat - The desired output format of the key as a string.
 * @returns {string} The generated key as a string.
 */
export function crypto_aead_aegis256_keygen(
  outputFormat: StringOutputFormat,
): string;
export function crypto_aead_aegis256_keygen(
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(crypto_aead_aegis256_keygen, outputFormat);
}

/**
 * Computes the authentication tag for a message using a key.
 *
 * @param {string | Uint8Array} message - The message to authenticate.
 * @param {Uint8Array} key - The key used for authentication.
 * @param {Uint8ArrayOutputFormat | null} [outputFormat=null] - The desired output format. Defaults to `Uint8Array`.
 * @returns {Uint8Array} The authentication tag in `Uint8Array` format.
 */
export function crypto_auth(
  message: string | Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
/**
 * Computes the authentication tag for a message using a key.
 *
 * @param {string | Uint8Array} message - The message to authenticate.
 * @param {Uint8Array} key - The key used for authentication.
 * @param {StringOutputFormat} outputFormat - The desired output format as a string.
 * @returns {string} The authentication tag as a string.
 */
export function crypto_auth(
  message: string | Uint8Array,
  key: Uint8Array,
  outputFormat: StringOutputFormat,
): string;
export function crypto_auth(
  message: string | Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(crypto_auth, message, key, outputFormat);
}

/**
 * Generates a key for use with the authentication algorithm.
 *
 * @param {Uint8ArrayOutputFormat | null} [outputFormat=null] - The desired output format. Defaults to `Uint8Array`.
 * @returns {Uint8Array} The generated key in `Uint8Array` format.
 */
export function crypto_auth_keygen(
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
export function crypto_auth_keygen(outputFormat: StringOutputFormat): string;
/**
 * Generates a key for use with the authentication algorithm.
 *
 * @param {StringOutputFormat} outputFormat - The desired output format as a string.
 * @returns {string} The generated key as a string.
 */
export function crypto_auth_keygen(
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(crypto_auth_keygen, outputFormat);
}

/**
 * Verifies the authenticity of a message using a provided authentication tag and key.
 *
 * @param {Uint8Array} tag - The authentication tag to verify.
 * @param {string | Uint8Array} message - The message to verify.
 * @param {Uint8Array} key - The key used for verification.
 * @returns {boolean} `true` if the authentication tag is valid, `false` otherwise.
 */
export function crypto_auth_verify(
  tag: Uint8Array,
  message: string | Uint8Array,
  key: Uint8Array,
): boolean {
  return execute(crypto_auth_verify, tag, message, key);
}

/**
 * Precomputes the shared key for use in further `crypto_box` operations.
 *
 * @param {Uint8Array} publicKey - The recipient's public key.
 * @param {Uint8Array} privateKey - The sender's private key.
 * @param {Uint8ArrayOutputFormat | null} [outputFormat=null] - The desired output format. Defaults to `Uint8Array`.
 * @returns {Uint8Array} The precomputed shared key in `Uint8Array` format.
 */
export function crypto_box_beforenm(
  publicKey: Uint8Array,
  privateKey: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
/**
 * Precomputes the shared key for use in further `crypto_box` operations.
 *
 * @param {Uint8Array} publicKey - The recipient's public key.
 * @param {Uint8Array} privateKey - The sender's private key.
 * @param {StringOutputFormat} outputFormat - The desired output format as a string.
 * @returns {string} The precomputed shared key as a string.
 */
export function crypto_box_beforenm(
  publicKey: Uint8Array,
  privateKey: Uint8Array,
  outputFormat: StringOutputFormat,
): string;
export function crypto_box_beforenm(
  publicKey: Uint8Array,
  privateKey: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(crypto_box_beforenm, publicKey, privateKey, outputFormat);
}

/**
 * Encrypts a message using `crypto_box` and returns a detached ciphertext with a MAC (authentication tag).
 *
 * @param {string | Uint8Array} message - The plaintext message to encrypt.
 * @param {Uint8Array} nonce - The nonce to use for encryption.
 * @param {Uint8Array} publicKey - The recipient's public key.
 * @param {Uint8Array} privateKey - The sender's private key.
 * @param {Uint8ArrayOutputFormat | null} [outputFormat=null] - The desired output format. Defaults to `CryptoBox`.
 * @returns {CryptoBox} The encrypted message and MAC in `CryptoBox` format.
 */
export function crypto_box_detached(
  message: string | Uint8Array,
  nonce: Uint8Array,
  publicKey: Uint8Array,
  privateKey: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): CryptoBox;
/**
 * Encrypts a message using `crypto_box` and returns a detached ciphertext with a MAC (authentication tag).
 *
 * @param {string | Uint8Array} message - The plaintext message to encrypt.
 * @param {Uint8Array} nonce - The nonce to use for encryption.
 * @param {Uint8Array} publicKey - The recipient's public key.
 * @param {Uint8Array} privateKey - The sender's private key.
 * @param {StringOutputFormat} outputFormat - The desired output format as a string.
 * @returns {StringCryptoBox} The encrypted message and MAC as a string in `StringCryptoBox` format.
 */
export function crypto_box_detached(
  message: string | Uint8Array,
  nonce: Uint8Array,
  publicKey: Uint8Array,
  privateKey: Uint8Array,
  outputFormat: StringOutputFormat,
): StringCryptoBox;
export function crypto_box_detached(
  message: string | Uint8Array,
  nonce: Uint8Array,
  publicKey: Uint8Array,
  privateKey: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): CryptoBox | StringCryptoBox {
  return execute(
    crypto_box_detached,
    message,
    nonce,
    publicKey,
    privateKey,
    outputFormat,
  );
}

/**
 * Encrypts a message using `crypto_box` with the given nonce and key pair.
 *
 * @param {string | Uint8Array} message - The plaintext message to encrypt.
 * @param {Uint8Array} nonce - The nonce to use for encryption.
 * @param {Uint8Array} publicKey - The recipient's public key.
 * @param {Uint8Array} privateKey - The sender's private key.
 * @param {Uint8ArrayOutputFormat | null} [outputFormat=null] - The desired output format. Defaults to `Uint8Array`.
 * @returns {Uint8Array} The encrypted ciphertext in `Uint8Array` format.
 */
export function crypto_box_easy(
  message: string | Uint8Array,
  nonce: Uint8Array,
  publicKey: Uint8Array,
  privateKey: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
/**
 * Encrypts a message using `crypto_box` with the given nonce and key pair.
 *
 * @param {string | Uint8Array} message - The plaintext message to encrypt.
 * @param {Uint8Array} nonce - The nonce to use for encryption.
 * @param {Uint8Array} publicKey - The recipient's public key.
 * @param {Uint8Array} privateKey - The sender's private key.
 * @param {StringOutputFormat} outputFormat - The desired output format as a string.
 * @returns {string} The encrypted ciphertext as a string.
 */
export function crypto_box_easy(
  message: string | Uint8Array,
  nonce: Uint8Array,
  publicKey: Uint8Array,
  privateKey: Uint8Array,
  outputFormat: StringOutputFormat,
): string;
export function crypto_box_easy(
  message: string | Uint8Array,
  nonce: Uint8Array,
  publicKey: Uint8Array,
  privateKey: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(
    crypto_box_easy,
    message,
    nonce,
    publicKey,
    privateKey,
    outputFormat,
  );
}

/**
 * Encrypts a message using `crypto_box` with a shared key (post key exchange).
 *
 * @param {string | Uint8Array} message - The plaintext message to encrypt.
 * @param {Uint8Array} nonce - The nonce to use for encryption.
 * @param {Uint8Array} sharedKey - The precomputed shared key.
 * @param {Uint8ArrayOutputFormat | null} [outputFormat=null] - The desired output format. Defaults to `Uint8Array`.
 * @returns {Uint8Array} The encrypted ciphertext in `Uint8Array` format.
 */
export function crypto_box_easy_afternm(
  message: string | Uint8Array,
  nonce: Uint8Array,
  sharedKey: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
/**
 * Encrypts a message using `crypto_box` with a shared key (post key exchange).
 *
 * @param {string | Uint8Array} message - The plaintext message to encrypt.
 * @param {Uint8Array} nonce - The nonce to use for encryption.
 * @param {Uint8Array} sharedKey - The precomputed shared key.
 * @param {StringOutputFormat} outputFormat - The desired output format as a string.
 * @returns {string} The encrypted ciphertext as a string.
 */
export function crypto_box_easy_afternm(
  message: string | Uint8Array,
  nonce: Uint8Array,
  sharedKey: Uint8Array,
  outputFormat: StringOutputFormat,
): string;
export function crypto_box_easy_afternm(
  message: string | Uint8Array,
  nonce: Uint8Array,
  sharedKey: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(
    crypto_box_easy_afternm,
    message,
    nonce,
    sharedKey,
    outputFormat,
  );
}

/**
 * Generates a new key pair for `crypto_box` operations.
 *
 * @param {Uint8ArrayOutputFormat | null} [outputFormat=null] - The desired output format. Defaults to `KeyPair`.
 * @returns {KeyPair} The generated key pair in `KeyPair` format.
 */
export function crypto_box_keypair(
  outputFormat?: Uint8ArrayOutputFormat | null,
): KeyPair;
/**
 * Generates a new key pair for `crypto_box` operations.
 *
 * @param {StringOutputFormat} outputFormat - The desired output format as a string.
 * @returns {string} The generated key pair as a string.
 */
export function crypto_box_keypair(
  outputFormat: StringOutputFormat,
): StringKeyPair;
export function crypto_box_keypair(
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): KeyPair | StringKeyPair {
  return execute(crypto_box_keypair, outputFormat);
}

/**
 * Decrypts a ciphertext with detached MAC using a private key and a public key.
 *
 * @param {string | Uint8Array} ciphertext - The ciphertext to decrypt.
 * @param {Uint8Array} mac - The detached MAC for integrity verification.
 * @param {Uint8Array} nonce - The nonce used for encryption.
 * @param {Uint8Array} publicKey - The public key of the recipient.
 * @param {Uint8Array} privateKey - The private key of the recipient.
 * @param {Uint8ArrayOutputFormat | null} [outputFormat=null] - The desired output format. Defaults to `Uint8Array`.
 * @returns {Uint8Array} The decrypted message in `Uint8Array` format.
 */
export function crypto_box_open_detached(
  ciphertext: string | Uint8Array,
  mac: Uint8Array,
  nonce: Uint8Array,
  publicKey: Uint8Array,
  privateKey: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
/**
 * Decrypts a ciphertext with detached MAC using a private key and a public key.
 *
 * @param {string | Uint8Array} ciphertext - The ciphertext to decrypt.
 * @param {Uint8Array} mac - The detached MAC for integrity verification.
 * @param {Uint8Array} nonce - The nonce used for encryption.
 * @param {Uint8Array} publicKey - The public key of the recipient.
 * @param {Uint8Array} privateKey - The private key of the recipient.
 * @param {StringOutputFormat} outputFormat - The desired output format as a string.
 * @returns {string} The decrypted message as a string.
 */
export function crypto_box_open_detached(
  ciphertext: string | Uint8Array,
  mac: Uint8Array,
  nonce: Uint8Array,
  publicKey: Uint8Array,
  privateKey: Uint8Array,
  outputFormat: StringOutputFormat,
): string;
export function crypto_box_open_detached(
  ciphertext: string | Uint8Array,
  mac: Uint8Array,
  nonce: Uint8Array,
  publicKey: Uint8Array,
  privateKey: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(
    crypto_box_open_detached,
    ciphertext,
    mac,
    nonce,
    publicKey,
    privateKey,
    outputFormat,
  );
}

/**
 * Decrypts a ciphertext using a private key and a public key.
 *
 * @param {string | Uint8Array} ciphertext - The ciphertext to decrypt.
 * @param {Uint8Array} nonce - The nonce used for encryption.
 * @param {Uint8Array} publicKey - The public key of the recipient.
 * @param {Uint8Array} privateKey - The private key of the recipient.
 * @param {Uint8ArrayOutputFormat | null} [outputFormat=null] - The desired output format. Defaults to `Uint8Array`.
 * @returns {Uint8Array} The decrypted message in `Uint8Array` format.
 */
export function crypto_box_open_easy(
  ciphertext: string | Uint8Array,
  nonce: Uint8Array,
  publicKey: Uint8Array,
  privateKey: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
/**
 * Decrypts a ciphertext using a private key and a public key.
 *
 * @param {string | Uint8Array} ciphertext - The ciphertext to decrypt.
 * @param {Uint8Array} nonce - The nonce used for encryption.
 * @param {Uint8Array} publicKey - The public key of the recipient.
 * @param {Uint8Array} privateKey - The private key of the recipient.
 * @param {StringOutputFormat} outputFormat - The desired output format as a string.
 * @returns {string} The decrypted message as a string.
 */
export function crypto_box_open_easy(
  ciphertext: string | Uint8Array,
  nonce: Uint8Array,
  publicKey: Uint8Array,
  privateKey: Uint8Array,
  outputFormat: StringOutputFormat,
): string;
export function crypto_box_open_easy(
  ciphertext: string | Uint8Array,
  nonce: Uint8Array,
  publicKey: Uint8Array,
  privateKey: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(
    crypto_box_open_easy,
    ciphertext,
    nonce,
    publicKey,
    privateKey,
    outputFormat,
  );
}

/**
 * Decrypts a ciphertext with a shared key and nonce.
 *
 * @param {string | Uint8Array} ciphertext - The ciphertext to decrypt.
 * @param {Uint8Array} nonce - The nonce used for encryption.
 * @param {Uint8Array} sharedKey - The shared key used for decryption.
 * @param {Uint8ArrayOutputFormat | null} [outputFormat=null] - The desired output format. Defaults to `Uint8Array`.
 * @returns {Uint8Array} The decrypted message in `Uint8Array` format.
 */
export function crypto_box_open_easy_afternm(
  ciphertext: string | Uint8Array,
  nonce: Uint8Array,
  sharedKey: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
/**
 * Decrypts a ciphertext with a shared key and nonce.
 *
 * @param {string | Uint8Array} ciphertext - The ciphertext to decrypt.
 * @param {Uint8Array} nonce - The nonce used for encryption.
 * @param {Uint8Array} sharedKey - The shared key used for decryption.
 * @param {StringOutputFormat} outputFormat - The desired output format as a string.
 * @returns {string} The decrypted message as a string.
 */
export function crypto_box_open_easy_afternm(
  ciphertext: string | Uint8Array,
  nonce: Uint8Array,
  sharedKey: Uint8Array,
  outputFormat: StringOutputFormat,
): string;
export function crypto_box_open_easy_afternm(
  ciphertext: string | Uint8Array,
  nonce: Uint8Array,
  sharedKey: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(
    crypto_box_open_easy_afternm,
    ciphertext,
    nonce,
    sharedKey,
    outputFormat,
  );
}

/**
 * Encrypts a message using a public key.
 *
 * @param {string | Uint8Array} message - The message to encrypt.
 * @param {Uint8Array} publicKey - The recipient's public key.
 * @param {Uint8ArrayOutputFormat | null} [outputFormat=null] - The desired output format. Defaults to `Uint8Array`.
 * @returns {Uint8Array} The encrypted ciphertext in `Uint8Array` format.
 */
export function crypto_box_seal(
  message: string | Uint8Array,
  publicKey: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
/**
 * Encrypts a message using a public key.
 *
 * @param {string | Uint8Array} message - The message to encrypt.
 * @param {Uint8Array} publicKey - The recipient's public key.
 * @param {StringOutputFormat} outputFormat - The desired output format as a string.
 * @returns {string} The encrypted ciphertext as a string.
 */
export function crypto_box_seal(
  message: string | Uint8Array,
  publicKey: Uint8Array,
  outputFormat: StringOutputFormat,
): string;
export function crypto_box_seal(
  message: string | Uint8Array,
  publicKey: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(
    crypto_box_seal,
    message,
    publicKey,
    outputFormat,
  );
}

/**
 * Decrypts a sealed ciphertext using the private key.
 *
 * @param {string | Uint8Array} ciphertext - The sealed ciphertext to decrypt.
 * @param {Uint8Array} publicKey - The recipient's public key.
 * @param {Uint8Array} privateKey - The recipient's private key.
 * @param {Uint8ArrayOutputFormat | null} [outputFormat=null] - The desired output format. Defaults to `Uint8Array`.
 * @returns {Uint8Array} The decrypted message in `Uint8Array` format.
 */
export function crypto_box_seal_open(
  ciphertext: string | Uint8Array,
  publicKey: Uint8Array,
  privateKey: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
/**
 * Decrypts a sealed ciphertext using the private key.
 *
 * @param {string | Uint8Array} ciphertext - The sealed ciphertext to decrypt.
 * @param {Uint8Array} publicKey - The recipient's public key.
 * @param {Uint8Array} privateKey - The recipient's private key.
 * @param {StringOutputFormat} outputFormat - The desired output format as a string.
 * @returns {string} The decrypted message as a string.
 */
export function crypto_box_seal_open(
  ciphertext: string | Uint8Array,
  publicKey: Uint8Array,
  privateKey: Uint8Array,
  outputFormat: StringOutputFormat,
): string;
export function crypto_box_seal_open(
  ciphertext: string | Uint8Array,
  publicKey: Uint8Array,
  privateKey: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(
    crypto_box_seal_open,
    ciphertext,
    publicKey,
    privateKey,
    outputFormat,
  );
}

/**
 * Generates a key pair using a seed.
 *
 * @param {Uint8Array} seed - The seed to generate the key pair from.
 * @param {Uint8ArrayOutputFormat | null} [outputFormat=null] - The desired output format. Defaults to `KeyPair`.
 * @returns {KeyPair} The generated key pair in `KeyPair` format.
 */
export function crypto_box_seed_keypair(
  seed: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): KeyPair;
/**
 * Generates a key pair using a seed.
 *
 * @param {Uint8Array} seed - The seed to generate the key pair from.
 * @param {StringOutputFormat} outputFormat - The desired output format as a string.
 * @returns {StringKeyPair} The generated key pair as a string.
 */
export function crypto_box_seed_keypair(
  seed: Uint8Array,
  outputFormat: StringOutputFormat,
): StringKeyPair;
export function crypto_box_seed_keypair(
  seed: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): KeyPair | StringKeyPair {
  return execute(crypto_box_seed_keypair, seed, outputFormat);
}

/**
 * Computes a cryptographic hash of the input message.
 *
 * @param {number} hash_length - The length of the output hash.
 * @param {string | Uint8Array} message - The message to hash.
 * @param {string | Uint8Array | null} [key=null] - The optional key for the hash function.
 * @param {Uint8ArrayOutputFormat | null} [outputFormat=null] - The desired output format. Defaults to `Uint8Array`.
 * @returns {Uint8Array} The computed hash in `Uint8Array` format.
 */
export function crypto_generichash(
  hash_length: number,
  message: string | Uint8Array,
  key?: string | Uint8Array | null,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
/**
 * Computes a cryptographic hash of the input message.
 *
 * @param {number} hash_length - The length of the output hash.
 * @param {string | Uint8Array} message - The message to hash.
 * @param {string | Uint8Array | null} [key=null] - The optional key for the hash function.
 * @param {StringOutputFormat} outputFormat - The desired output format as a string.
 * @returns {string} The computed hash as a string.
 */
export function crypto_generichash(
  hash_length: number,
  message: string | Uint8Array,
  key: string | Uint8Array | null,
  outputFormat: StringOutputFormat,
): string;
export function crypto_generichash(
  hash_length: number,
  message: string | Uint8Array,
  key?: string | Uint8Array | null,
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(crypto_generichash, hash_length, message, key, outputFormat);
}

export function crypto_generichash_final(
  state_address: StateAddress,
  hash_length: number,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
export function crypto_generichash_final(
  state_address: StateAddress,
  hash_length: number,
  outputFormat: StringOutputFormat,
): string;
export function crypto_generichash_final(
  state_address: StateAddress,
  hash_length: number,
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(
    crypto_generichash_final,
    state_address,
    hash_length,
    outputFormat,
  );
}

/**
 * Initializes the state for a generic hash computation.
 *
 * @param {string | Uint8Array | null} key - The key for the hash function, or `null` if no key is used.
 * @param {number} hash_length - The length of the desired hash output.
 * @returns {StateAddress} The state address to be used with subsequent `update` and `final` operations.
 */
export function crypto_generichash_init(
  key: string | Uint8Array | null,
  hash_length: number,
): StateAddress {
  return execute(crypto_generichash_init, key, hash_length);
}

/**
 * Generates a new key for the generic hash function.
 *
 * @param {Uint8ArrayOutputFormat | null} [outputFormat=null] - The desired output format. Defaults to `Uint8Array`.
 * @returns {Uint8Array} The generated key in `Uint8Array` format.
 */
export function crypto_generichash_keygen(
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
/**
 * Generates a new key for the generic hash function.
 *
 * @param {StringOutputFormat} outputFormat - The desired output format as a string.
 * @returns {string} The generated key as a string.
 */
export function crypto_generichash_keygen(
  outputFormat: StringOutputFormat,
): string;
export function crypto_generichash_keygen(
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(crypto_generichash_keygen, outputFormat);
}

/**
 * Updates the state of the generic hash computation with a new message chunk.
 *
 * @param {StateAddress} state_address - The state address obtained from `crypto_generichash_init`.
 * @param {string | Uint8Array} message_chunk - The new chunk of the message to hash.
 */
export function crypto_generichash_update(
  state_address: StateAddress,
  message_chunk: string | Uint8Array,
): void {
  return execute(crypto_generichash_update, state_address, message_chunk);
}

/**
 * Computes a cryptographic hash of the input message.
 *
 * @param {string | Uint8Array} message - The message to hash.
 * @param {Uint8ArrayOutputFormat | null} [outputFormat=null] - The desired output format. Defaults to `Uint8Array`.
 * @returns {Uint8Array} The computed hash in `Uint8Array` format.
 */
export function crypto_hash(
  message: string | Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
/**
 * Computes a cryptographic hash of the input message.
 *
 * @param {string | Uint8Array} message - The message to hash.
 * @param {StringOutputFormat} outputFormat - The desired output format as a string.
 * @returns {string} The computed hash as a string.
 */
export function crypto_hash(
  message: string | Uint8Array,
  outputFormat: StringOutputFormat,
): string;
export function crypto_hash(
  message: string | Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(crypto_hash, message, outputFormat);
}

/**
 * Derives a subkey from a master key using the Key Derivation Function (KDF).
 *
 * @param {number} subkey_len - The length of the derived subkey.
 * @param {number} subkey_id - The identifier for the subkey to be derived.
 * @param {string} ctx - The context (application-specific string) used in the derivation process.
 * @param {Uint8Array} key - The master key from which the subkey is derived.
 * @param {Uint8ArrayOutputFormat | null} [outputFormat=null] - The desired output format. Defaults to `Uint8Array`.
 * @returns {Uint8Array} The derived subkey in `Uint8Array` format.
 */
export function crypto_kdf_derive_from_key(
  subkey_len: number,
  subkey_id: number,
  ctx: string,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
/**
 * Derives a subkey from a master key using the Key Derivation Function (KDF).
 *
 * @param {number} subkey_len - The length of the derived subkey.
 * @param {number} subkey_id - The identifier for the subkey to be derived.
 * @param {string} ctx - The context (application-specific string) used in the derivation process.
 * @param {Uint8Array} key - The master key from which the subkey is derived.
 * @param {StringOutputFormat} outputFormat - The desired output format as a string.
 * @returns {string} The derived subkey as a string.
 */
export function crypto_kdf_derive_from_key(
  subkey_len: number,
  subkey_id: number,
  ctx: string,
  key: Uint8Array,
  outputFormat: StringOutputFormat,
): string;
export function crypto_kdf_derive_from_key(
  subkey_len: number,
  subkey_id: number,
  ctx: string,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(
    crypto_kdf_derive_from_key,
    subkey_len,
    subkey_id,
    ctx,
    key,
    outputFormat,
  );
}

/**
 * Generates a new key for use with the Key Derivation Function (KDF).
 *
 * @param {Uint8ArrayOutputFormat | null} [outputFormat=null] - The desired output format. Defaults to `Uint8Array`.
 * @returns {Uint8Array} The generated key in `Uint8Array` format.
 */
export function crypto_kdf_keygen(
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
/**
 * Generates a new key for use with the Key Derivation Function (KDF).
 *
 * @param {StringOutputFormat} outputFormat - The desired output format as a string.
 * @returns {string} The generated key as a string.
 */
export function crypto_kdf_keygen(outputFormat: StringOutputFormat): string;
export function crypto_kdf_keygen(
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(crypto_kdf_keygen, outputFormat);
}

/**
 * Derives the session keys for the client in a key exchange protocol.
 *
 * @param {Uint8Array} clientPublicKey - The client's public key.
 * @param {Uint8Array} clientSecretKey - The client's secret key.
 * @param {Uint8Array} serverPublicKey - The server's public key.
 * @param {Uint8ArrayOutputFormat | null} [outputFormat=null] - The desired output format. Defaults to `Uint8Array`.
 * @returns {CryptoKX} The derived client session keys.
 */
export function crypto_kx_client_session_keys(
  clientPublicKey: Uint8Array,
  clientSecretKey: Uint8Array,
  serverPublicKey: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): CryptoKX;
/**
 * Derives the session keys for the client in a key exchange protocol.
 *
 * @param {Uint8Array} clientPublicKey - The client's public key.
 * @param {Uint8Array} clientSecretKey - The client's secret key.
 * @param {Uint8Array} serverPublicKey - The server's public key.
 * @param {StringOutputFormat} outputFormat - The desired output format as a string.
 * @returns {StringCryptoKX} The derived client session keys as a string.
 */
export function crypto_kx_client_session_keys(
  clientPublicKey: Uint8Array,
  clientSecretKey: Uint8Array,
  serverPublicKey: Uint8Array,
  outputFormat: StringOutputFormat,
): StringCryptoKX;
export function crypto_kx_client_session_keys(
  clientPublicKey: Uint8Array,
  clientSecretKey: Uint8Array,
  serverPublicKey: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): CryptoKX | StringCryptoKX {
  return execute(
    crypto_kx_client_session_keys,
    clientPublicKey,
    clientSecretKey,
    serverPublicKey,
    outputFormat,
  );
}

/**
 * Generates a key pair for use in a key exchange protocol.
 *
 * @param {Uint8ArrayOutputFormat | null} [outputFormat=null] - The desired output format. Defaults to `KeyPair`.
 * @returns {KeyPair} The generated key pair in `KeyPair` format.
 */
export function crypto_kx_keypair(
  outputFormat?: Uint8ArrayOutputFormat | null,
): KeyPair;
/**
 * Generates a key pair for use in a key exchange protocol.
 *
 * @param {StringOutputFormat} outputFormat - The desired output format as a string.
 * @returns {StringKeyPair} The generated key pair as a string.
 */
export function crypto_kx_keypair(
  outputFormat: StringOutputFormat,
): StringKeyPair;
export function crypto_kx_keypair(
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): KeyPair | StringKeyPair {
  return execute(crypto_kx_keypair, outputFormat);
}

/**
 * Generates a key pair for use in a key exchange protocol based on a given seed.
 *
 * @param {Uint8Array} seed - The seed used to generate the key pair.
 * @param {Uint8ArrayOutputFormat | null} [outputFormat=null] - The desired output format. Defaults to `KeyPair`.
 * @returns {KeyPair} The generated key pair in `KeyPair` format.
 */
export function crypto_kx_seed_keypair(
  seed: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): KeyPair;
/**
 * Generates a key pair for use in a key exchange protocol based on a given seed.
 *
 * @param {Uint8Array} seed - The seed used to generate the key pair.
 * @param {StringOutputFormat} outputFormat - The desired output format as a string.
 * @returns {StringKeyPair} The generated key pair as a string.
 */
export function crypto_kx_seed_keypair(
  seed: Uint8Array,
  outputFormat: StringOutputFormat,
): StringKeyPair;
export function crypto_kx_seed_keypair(
  seed: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): KeyPair | StringKeyPair {
  return execute(crypto_kx_seed_keypair, seed, outputFormat);
}

/**
 * Derives the session keys for the server in a key exchange protocol.
 *
 * @param {Uint8Array} serverPublicKey - The server's public key.
 * @param {Uint8Array} serverSecretKey - The server's secret key.
 * @param {Uint8Array} clientPublicKey - The client's public key.
 * @param {Uint8ArrayOutputFormat | null} [outputFormat=null] - The desired output format. Defaults to `CryptoKX`.
 * @returns {CryptoKX} The derived server session keys.
 */
export function crypto_kx_server_session_keys(
  serverPublicKey: Uint8Array,
  serverSecretKey: Uint8Array,
  clientPublicKey: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): CryptoKX;
/**
 * Derives the session keys for the server in a key exchange protocol.
 *
 * @param {Uint8Array} serverPublicKey - The server's public key.
 * @param {Uint8Array} serverSecretKey - The server's secret key.
 * @param {Uint8Array} clientPublicKey - The client's public key.
 * @param {StringOutputFormat} outputFormat - The desired output format as a string.
 * @returns {StringCryptoKX} The derived server session keys as a string.
 */
export function crypto_kx_server_session_keys(
  serverPublicKey: Uint8Array,
  serverSecretKey: Uint8Array,
  clientPublicKey: Uint8Array,
  outputFormat: StringOutputFormat,
): StringCryptoKX;
export function crypto_kx_server_session_keys(
  serverPublicKey: Uint8Array,
  serverSecretKey: Uint8Array,
  clientPublicKey: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): CryptoKX | StringCryptoKX {
  return execute(
    crypto_kx_server_session_keys,
    serverPublicKey,
    serverSecretKey,
    clientPublicKey,
    outputFormat,
  );
}

/**
 * Hashes a password using a cryptographic hashing function.
 *
 * @param {number} keyLength - The desired length of the output hash.
 * @param {string | Uint8Array} password - The password to hash.
 * @param {Uint8Array} salt - The salt to use in the hashing process.
 * @param {number} opsLimit - The CPU cost factor for hashing.
 * @param {number} memLimit - The memory cost factor for hashing.
 * @param {number} algorithm - The hashing algorithm to use.
 * @param {Uint8ArrayOutputFormat | null} [outputFormat=null] - The desired output format. Defaults to `Uint8Array`.
 * @returns {Uint8Array} The hashed password in `Uint8Array` format.
 */
export function crypto_pwhash(
  keyLength: number,
  password: string | Uint8Array,
  salt: Uint8Array,
  opsLimit: number,
  memLimit: number,
  algorithm: number,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
/**
 * Hashes a password using a cryptographic hashing function.
 *
 * @param {number} keyLength - The desired length of the output hash.
 * @param {string | Uint8Array} password - The password to hash.
 * @param {Uint8Array} salt - The salt to use in the hashing process.
 * @param {number} opsLimit - The CPU cost factor for hashing.
 * @param {number} memLimit - The memory cost factor for hashing.
 * @param {number} algorithm - The hashing algorithm to use.
 * @param {StringOutputFormat} outputFormat - The desired output format as a string.
 * @returns {string} The hashed password as a string.
 */
export function crypto_pwhash(
  keyLength: number,
  password: string | Uint8Array,
  salt: Uint8Array,
  opsLimit: number,
  memLimit: number,
  algorithm: number,
  outputFormat: StringOutputFormat,
): string;
export function crypto_pwhash(
  keyLength: number,
  password: string | Uint8Array,
  salt: Uint8Array,
  opsLimit: number,
  memLimit: number,
  algorithm: number,
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(
    crypto_pwhash,
    keyLength,
    password,
    salt,
    opsLimit,
    memLimit,
    algorithm,
    outputFormat,
  );
}

/**
 * Hashes a password using a cryptographic function and returns a string.
 *
 * @param {string | Uint8Array} password - The password to hash.
 * @param {number} opsLimit - The CPU cost factor for hashing.
 * @param {number} memLimit - The memory cost factor for hashing.
 * @returns {string} The hashed password as a string.
 */
export function crypto_pwhash_str(
  password: string | Uint8Array,
  opsLimit: number,
  memLimit: number,
): string {
  return execute(crypto_pwhash_str, password, opsLimit, memLimit);
}

/**
 * Verifies if the password matches the hashed password.
 *
 * @param {string} hashed_password - The hashed password to verify against.
 * @param {string | Uint8Array} password - The password to verify.
 * @returns {boolean} `true` if the password matches the hashed password, `false` otherwise.
 */
export function crypto_pwhash_str_verify(
  hashed_password: string,
  password: string | Uint8Array,
): boolean {
  return execute(crypto_pwhash_str_verify, hashed_password, password);
}

/**
 * Checks if the hashed password needs to be rehashed based on new cost parameters.
 *
 * @param {string} hashedPassword - The hashed password to check.
 * @param {number} opsLimit - The new CPU cost factor.
 * @param {number} memLimit - The new memory cost factor.
 * @returns {boolean} `true` if the password needs rehashing, `false` otherwise.
 */
export function crypto_pwhash_str_needs_rehash(
  hashedPassword: string,
  opsLimit: number,
  memLimit: number,
): boolean {
  return execute(
    crypto_pwhash_str_needs_rehash,
    hashedPassword,
    opsLimit,
    memLimit,
  );
}

/**
 * Computes the scalar multiplication of two elliptic curve points.
 *
 * @param {Uint8Array} privateKey - The private key for scalar multiplication.
 * @param {Uint8Array} publicKey - The public key for scalar multiplication.
 * @param {Uint8ArrayOutputFormat | null} [outputFormat=null] - The desired output format. Defaults to `Uint8Array`.
 * @returns {Uint8Array} The resulting elliptic curve point in `Uint8Array` format.
 */
export function crypto_scalarmult(
  privateKey: Uint8Array,
  publicKey: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
/**
 * Computes the scalar multiplication of two elliptic curve points.
 *
 * @param {Uint8Array} privateKey - The private key for scalar multiplication.
 * @param {Uint8Array} publicKey - The public key for scalar multiplication.
 * @param {StringOutputFormat} outputFormat - The desired output format as a string.
 * @returns {string} The resulting elliptic curve point as a string.
 */
export function crypto_scalarmult(
  privateKey: Uint8Array,
  publicKey: Uint8Array,
  outputFormat: StringOutputFormat,
): string;
export function crypto_scalarmult(
  privateKey: Uint8Array,
  publicKey: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(crypto_scalarmult, privateKey, publicKey, outputFormat);
}

/**
 * Computes the scalar multiplication of the base point with a private key.
 *
 * @param {Uint8Array} privateKey - The private key for scalar multiplication with the base point.
 * @param {Uint8ArrayOutputFormat | null} [outputFormat=null] - The desired output format. Defaults to `Uint8Array`.
 * @returns {Uint8Array} The resulting elliptic curve point in `Uint8Array` format.
 */
export function crypto_scalarmult_base(
  privateKey: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
/**
 * Computes the scalar multiplication of the base point with a private key.
 *
 * @param {Uint8Array} privateKey - The private key for scalar multiplication with the base point.
 * @param {StringOutputFormat} outputFormat - The desired output format as a string.
 * @returns {string} The resulting elliptic curve point as a string.
 */
export function crypto_scalarmult_base(
  privateKey: Uint8Array,
  outputFormat: StringOutputFormat,
): string;
export function crypto_scalarmult_base(
  privateKey: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(crypto_scalarmult_base, privateKey, outputFormat);
}

/**
 * Encrypts a message with a secret key and returns a detached ciphertext and MAC.
 *
 * @param {string | Uint8Array} message - The plaintext message to encrypt.
 * @param {Uint8Array} nonce - The nonce used for encryption.
 * @param {Uint8Array} key - The secret key used for encryption.
 * @param {Uint8ArrayOutputFormat | null} [outputFormat=null] - The desired output format. Defaults to `SecretBox`.
 * @returns {SecretBox} The encrypted message and MAC in `SecretBox` format.
 */
export function crypto_secretbox_detached(
  message: string | Uint8Array,
  nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): SecretBox;
/**
 * Encrypts a message with a secret key and returns a detached ciphertext and MAC.
 *
 * @param {string | Uint8Array} message - The plaintext message to encrypt.
 * @param {Uint8Array} nonce - The nonce used for encryption.
 * @param {Uint8Array} key - The secret key used for encryption.
 * @param {StringOutputFormat} outputFormat - The desired output format as a string.
 * @returns {StringSecretBox} The encrypted message and MAC as a string in `StringSecretBox` format.
 */
export function crypto_secretbox_detached(
  message: string | Uint8Array,
  nonce: Uint8Array,
  key: Uint8Array,
  outputFormat: StringOutputFormat,
): StringSecretBox;
export function crypto_secretbox_detached(
  message: string | Uint8Array,
  nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): SecretBox | StringSecretBox {
  return execute(crypto_secretbox_detached, message, nonce, key, outputFormat);
}

/**
 * Encrypts a message with a secret key and returns the ciphertext.
 *
 * @param {string | Uint8Array} message - The plaintext message to encrypt.
 * @param {Uint8Array} nonce - The nonce used for encryption.
 * @param {Uint8Array} key - The secret key used for encryption.
 * @param {Uint8ArrayOutputFormat | null} [outputFormat=null] - The desired output format. Defaults to `Uint8Array`.
 * @returns {Uint8Array} The encrypted ciphertext in `Uint8Array` format.
 */
export function crypto_secretbox_easy(
  message: string | Uint8Array,
  nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
/**
 * Encrypts a message with a secret key and returns the ciphertext.
 *
 * @param {string | Uint8Array} message - The plaintext message to encrypt.
 * @param {Uint8Array} nonce - The nonce used for encryption.
 * @param {Uint8Array} key - The secret key used for encryption.
 * @param {StringOutputFormat} outputFormat - The desired output format as a string.
 * @returns {string} The encrypted ciphertext as a string.
 */
export function crypto_secretbox_easy(
  message: string | Uint8Array,
  nonce: Uint8Array,
  key: Uint8Array,
  outputFormat: StringOutputFormat,
): string;
export function crypto_secretbox_easy(
  message: string | Uint8Array,
  nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(crypto_secretbox_easy, message, nonce, key, outputFormat);
}

/**
 * Generates a secret key for use with `crypto_secretbox`.
 *
 * @param {Uint8ArrayOutputFormat | null} [outputFormat=null] - The desired output format. Defaults to `Uint8Array`.
 * @returns {Uint8Array} The generated secret key in `Uint8Array` format.
 */
export function crypto_secretbox_keygen(
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
/**
 * Generates a secret key for use with `crypto_secretbox`.
 *
 * @param {StringOutputFormat} outputFormat - The desired output format as a string.
 * @returns {string} The generated secret key as a string.
 */
export function crypto_secretbox_keygen(
  outputFormat: StringOutputFormat,
): string;
export function crypto_secretbox_keygen(
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(crypto_secretbox_keygen, outputFormat);
}

/**
 * Opens a detached (authenticated) secret box, verifying its authenticity and decrypting the ciphertext.
 *
 * @param {string | Uint8Array} ciphertext - The encrypted data to be decrypted.
 * @param {Uint8Array} mac - The message authentication code (MAC) used to verify the integrity of the ciphertext.
 * @param {Uint8Array} nonce - The nonce used in the encryption process.
 * @param {Uint8Array} key - The secret key used to decrypt the ciphertext.
 * @param {Uint8ArrayOutputFormat | null} [outputFormat=null] - The desired output format. Defaults to `Uint8Array`.
 * @returns {Uint8Array} The decrypted plaintext.
 */
export function crypto_secretbox_open_detached(
  ciphertext: string | Uint8Array,
  mac: Uint8Array,
  nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;

/**
 * Opens a detached (authenticated) secret box, verifying its authenticity and decrypting the ciphertext.
 *
 * @param {string | Uint8Array} ciphertext - The encrypted data to be decrypted.
 * @param {Uint8Array} mac - The message authentication code (MAC) used to verify the integrity of the ciphertext.
 * @param {Uint8Array} nonce - The nonce used in the encryption process.
 * @param {Uint8Array} key - The secret key used to decrypt the ciphertext.
 * @param {StringOutputFormat} outputFormat - The desired output format as a string.
 * @returns {string} The decrypted plaintext as a string.
 */
export function crypto_secretbox_open_detached(
  ciphertext: string | Uint8Array,
  mac: Uint8Array,
  nonce: Uint8Array,
  key: Uint8Array,
  outputFormat: StringOutputFormat,
): string;
export function crypto_secretbox_open_detached(
  ciphertext: string | Uint8Array,
  mac: Uint8Array,
  nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(
    crypto_secretbox_open_detached,
    ciphertext,
    mac,
    nonce,
    key,
    outputFormat,
  );
}

/**
 * Opens a secret box and decrypts the ciphertext.
 *
 * @param {string | Uint8Array} ciphertext - The encrypted data to be decrypted.
 * @param {Uint8Array} nonce - The nonce used in the encryption process.
 * @param {Uint8Array} key - The secret key used to decrypt the ciphertext.
 * @param {Uint8ArrayOutputFormat | null} [outputFormat=null] - The desired output format. Defaults to `Uint8Array`.
 * @returns {Uint8Array} The decrypted plaintext.
 */
export function crypto_secretbox_open_easy(
  ciphertext: string | Uint8Array,
  nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
/**
 * Opens a secret box and decrypts the ciphertext.
 *
 * @param {string | Uint8Array} ciphertext - The encrypted data to be decrypted.
 * @param {Uint8Array} nonce - The nonce used in the encryption process.
 * @param {Uint8Array} key - The secret key used to decrypt the ciphertext.
 * @param {StringOutputFormat} outputFormat - The desired output format as a string.
 * @returns {string} The decrypted plaintext as a string.
 */
export function crypto_secretbox_open_easy(
  ciphertext: string | Uint8Array,
  nonce: Uint8Array,
  key: Uint8Array,
  outputFormat: StringOutputFormat,
): string;
export function crypto_secretbox_open_easy(
  ciphertext: string | Uint8Array,
  nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(
    crypto_secretbox_open_easy,
    ciphertext,
    nonce,
    key,
    outputFormat,
  );
}

/**
 * Initializes the decryption stream (pull) for the `xchacha20poly1305` stream cipher.
 *
 * @param {Uint8Array} header - The header used to initialize the stream, generated during the encryption.
 * @param {Uint8Array} key - The secret key used for decryption.
 * @returns {StateAddress} The state address for the decryption stream.
 */
export function crypto_secretstream_xchacha20poly1305_init_pull(
  header: Uint8Array,
  key: Uint8Array,
): StateAddress {
  return execute(crypto_secretstream_xchacha20poly1305_init_pull, header, key);
}

/**
 * Initializes the encryption stream (push) for the `xchacha20poly1305` stream cipher.
 *
 * @param {Uint8Array} key - The secret key used for encryption.
 * @param {Uint8ArrayOutputFormat | null} [outputFormat=null] - The desired output format. Defaults to an object with `state` and `header`.
 * @returns {Object} An object containing the state address and the header used for encryption.
 */
export function crypto_secretstream_xchacha20poly1305_init_push(
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): { state: StateAddress; header: Uint8Array };
/**
 * Initializes the encryption stream (push) for the `xchacha20poly1305` stream cipher.
 *
 * @param {Uint8Array} key - The secret key used for encryption.
 * @param {StringOutputFormat} outputFormat - The desired output format as a string.
 * @returns {Object} A string representation of an object containing the state and header.
 */
export function crypto_secretstream_xchacha20poly1305_init_push(
  key: Uint8Array,
  outputFormat: StringOutputFormat,
): { state: StateAddress; header: string };
export function crypto_secretstream_xchacha20poly1305_init_push(
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): { state: StateAddress; header: Uint8Array | string } {
  return execute(
    crypto_secretstream_xchacha20poly1305_init_push,
    key,
    outputFormat,
  );
}

/**
 * Generates a secret key for the `xchacha20poly1305` stream cipher.
 *
 * @param {Uint8ArrayOutputFormat | null} [outputFormat=null] - The desired output format. Defaults to `Uint8Array`.
 * @returns {Uint8Array} The generated secret key.
 */
export function crypto_secretstream_xchacha20poly1305_keygen(
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
/**
 * Generates a secret key for the `xchacha20poly1305` stream cipher.
 *
 * @param {StringOutputFormat} outputFormat - The desired output format as a string.
 * @returns {string} The generated secret key as a string.
 */
export function crypto_secretstream_xchacha20poly1305_keygen(
  outputFormat: StringOutputFormat,
): string;
export function crypto_secretstream_xchacha20poly1305_keygen(
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(crypto_secretstream_xchacha20poly1305_keygen, outputFormat);
}

/**
 * Pulls a message chunk from the `xchacha20poly1305` encryption stream, verifying its authenticity and decrypting it.
 *
 * @param {StateAddress} state_address - The state address of the decryption stream.
 * @param {string | Uint8Array} cipher - The ciphertext to be decrypted.
 * @param {string | Uint8Array | null} [ad=null] - Optional associated data that was used in the encryption.
 * @param {Uint8ArrayOutputFormat | null} [outputFormat=null] - The desired output format. Defaults to `Uint8Array`.
 * @returns {MessageTag} The decrypted message chunk along with its tag (e.g., `MessageTag` indicating if the message is complete).
 */
export function crypto_secretstream_xchacha20poly1305_pull(
  state_address: StateAddress,
  cipher: string | Uint8Array,
  ad?: string | Uint8Array | null,
  outputFormat?: Uint8ArrayOutputFormat | null,
): MessageTag;
/**
 * Pulls a message chunk from the `xchacha20poly1305` encryption stream, verifying its authenticity and decrypting it.
 *
 * @param {StateAddress} state_address - The state address of the decryption stream.
 * @param {string | Uint8Array} cipher - The ciphertext to be decrypted.
 * @param {string | Uint8Array | null} ad - Optional associated data that was used in the encryption.
 * @param {StringOutputFormat} outputFormat - The desired output format as a string.
 * @returns {StringMessageTag} The decrypted message chunk along with its tag as a string.
 */
export function crypto_secretstream_xchacha20poly1305_pull(
  state_address: StateAddress,
  cipher: string | Uint8Array,
  ad: string | Uint8Array | null,
  outputFormat: StringOutputFormat,
): StringMessageTag;
export function crypto_secretstream_xchacha20poly1305_pull(
  state_address: StateAddress,
  cipher: string | Uint8Array,
  ad?: string | Uint8Array | null,
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): MessageTag | StringMessageTag {
  return execute(
    crypto_secretstream_xchacha20poly1305_pull,
    state_address,
    cipher,
    ad,
    outputFormat,
  );
}

/**
 * Pushes a message chunk to the `xchacha20poly1305` encryption stream, encrypting it and appending the appropriate tag.
 *
 * @param {StateAddress} state_address - The state address of the encryption stream.
 * @param {string | Uint8Array} message_chunk - The message chunk to encrypt.
 * @param {string | Uint8Array | null} ad - Optional associated data that will be included in the encryption process.
 * @param {number} tag - A tag indicating whether the message is partial or final.
 * @param {Uint8ArrayOutputFormat | null} [outputFormat=null] - The desired output format. Defaults to `Uint8Array`.
 * @returns {Uint8Array} The encrypted message chunk with the tag.
 */
export function crypto_secretstream_xchacha20poly1305_push(
  state_address: StateAddress,
  message_chunk: string | Uint8Array,
  ad: string | Uint8Array | null,
  tag: number,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
/**
 * Pushes a message chunk to the `xchacha20poly1305` encryption stream, encrypting it and appending the appropriate tag.
 *
 * @param {StateAddress} state_address - The state address of the encryption stream.
 * @param {string | Uint8Array} message_chunk - The message chunk to encrypt.
 * @param {string | Uint8Array | null} ad - Optional associated data that will be included in the encryption process.
 * @param {number} tag - A tag indicating whether the message is partial or final.
 * @param {StringOutputFormat} outputFormat - The desired output format as a string.
 * @returns {string} The encrypted message chunk with the tag as a string.
 */
export function crypto_secretstream_xchacha20poly1305_push(
  state_address: StateAddress,
  message_chunk: string | Uint8Array,
  ad: string | Uint8Array | null,
  tag: number,
  outputFormat: StringOutputFormat,
): string;
export function crypto_secretstream_xchacha20poly1305_push(
  state_address: StateAddress,
  message_chunk: string | Uint8Array,
  ad: string | Uint8Array | null,
  tag: number,
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(
    crypto_secretstream_xchacha20poly1305_push,
    state_address,
    message_chunk,
    ad,
    tag,
    outputFormat,
  );
}

/**
 * Rekeys the `xchacha20poly1305` encryption stream, replacing the current key with a new one.
 *
 * @param {StateAddress} state_address - The state address of the encryption stream to be rekeyed.
 * @returns {true} A constant `true` indicating the operation was successful.
 */
export function crypto_secretstream_xchacha20poly1305_rekey(
  state_address: StateAddress,
): true {
  return execute(crypto_secretstream_xchacha20poly1305_rekey, state_address);
}

/**
 * Computes a short hash using a specific key and message.
 *
 * @param {string | Uint8Array} message - The message to hash.
 * @param {Uint8Array} key - The key used in the hash computation.
 * @param {Uint8ArrayOutputFormat | null} [outputFormat=null] - The desired output format. Defaults to `Uint8Array`.
 * @returns {Uint8Array} The resulting short hash.
 */
export function crypto_shorthash(
  message: string | Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
/**
 * Computes a short hash using a specific key and message.
 *
 * @param {string | Uint8Array} message - The message to hash.
 * @param {Uint8Array} key - The key used in the hash computation.
 * @param {StringOutputFormat} outputFormat - The desired output format as a string.
 * @returns {string} The resulting short hash as a string.
 */
export function crypto_shorthash(
  message: string | Uint8Array,
  key: Uint8Array,
  outputFormat: StringOutputFormat,
): string;
export function crypto_shorthash(
  message: string | Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(crypto_shorthash, message, key, outputFormat);
}

/**
 * Generates a key for short hashing.
 *
 * @param {Uint8ArrayOutputFormat | null} [outputFormat=null] - The desired output format. Defaults to `Uint8Array`.
 * @returns {Uint8Array} The generated key for short hashing.
 */
export function crypto_shorthash_keygen(
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
/**
 * Generates a key for short hashing.
 *
 * @param {StringOutputFormat} outputFormat - The desired output format as a string.
 * @returns {string} The generated key for short hashing as a string.
 */
export function crypto_shorthash_keygen(
  outputFormat: StringOutputFormat,
): string;
export function crypto_shorthash_keygen(
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(crypto_shorthash_keygen, outputFormat);
}

/**
 * Signs a message using a private key, creating a digital signature.
 *
 * @param {string | Uint8Array} message - The message to be signed.
 * @param {Uint8Array} privateKey - The private key used to sign the message.
 * @param {Uint8ArrayOutputFormat | null} [outputFormat=null] - The desired output format. Defaults to `Uint8Array`.
 * @returns {Uint8Array} The digital signature for the message.
 */
export function crypto_sign(
  message: string | Uint8Array,
  privateKey: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
/**
 * Signs a message using a private key, creating a digital signature.
 *
 * @param {string | Uint8Array} message - The message to be signed.
 * @param {Uint8Array} privateKey - The private key used to sign the message.
 * @param {StringOutputFormat} outputFormat - The desired output format as a string.
 * @returns {string} The digital signature for the message as a string.
 */
export function crypto_sign(
  message: string | Uint8Array,
  privateKey: Uint8Array,
  outputFormat: StringOutputFormat,
): string;
export function crypto_sign(
  message: string | Uint8Array,
  privateKey: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(crypto_sign, message, privateKey, outputFormat);
}

/**
 * Signs a message in a detached mode, producing a signature without modifying the original message.
 *
 * @param {string | Uint8Array} message - The message to be signed.
 * @param {Uint8Array} privateKey - The private key used to sign the message.
 * @param {Uint8ArrayOutputFormat | null} [outputFormat=null] - The desired output format. Defaults to `Uint8Array`.
 * @returns {Uint8Array} The detached signature for the message.
 */
export function crypto_sign_detached(
  message: string | Uint8Array,
  privateKey: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
/**
 * Signs a message in a detached mode, producing a signature without modifying the original message.
 *
 * @param {string | Uint8Array} message - The message to be signed.
 * @param {Uint8Array} privateKey - The private key used to sign the message.
 * @param {StringOutputFormat} outputFormat - The desired output format as a string.
 * @returns {string} The detached signature for the message as a string.
 */
export function crypto_sign_detached(
  message: string | Uint8Array,
  privateKey: Uint8Array,
  outputFormat: StringOutputFormat,
): string;
export function crypto_sign_detached(
  message: string | Uint8Array,
  privateKey: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(crypto_sign_detached, message, privateKey, outputFormat);
}

/**
 * Converts an Ed25519 public key to a Curve25519 public key.
 *
 * @param {Uint8Array} edPk - The Ed25519 public key to convert.
 * @param {Uint8ArrayOutputFormat | null} [outputFormat=null] - The desired output format. Defaults to `Uint8Array`.
 * @returns {Uint8Array} The corresponding Curve25519 public key.
 */
export function crypto_sign_ed25519_pk_to_curve25519(
  edPk: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
/**
 * Converts an Ed25519 public key to a Curve25519 public key.
 *
 * @param {Uint8Array} edPk - The Ed25519 public key to convert.
 * @param {StringOutputFormat} outputFormat - The desired output format as a string.
 * @returns {string} The corresponding Curve25519 public key as a string.
 */
export function crypto_sign_ed25519_pk_to_curve25519(
  edPk: Uint8Array,
  outputFormat: StringOutputFormat,
): string;
export function crypto_sign_ed25519_pk_to_curve25519(
  edPk: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(crypto_sign_ed25519_pk_to_curve25519, edPk, outputFormat);
}

/**
 * Converts an Ed25519 private key to a Curve25519 private key.
 *
 * @param {Uint8Array} edSk - The Ed25519 private key to convert.
 * @param {Uint8ArrayOutputFormat | null} [outputFormat=null] - The desired output format. Defaults to `Uint8Array`.
 * @returns {Uint8Array} The corresponding Curve25519 private key.
 */
export function crypto_sign_ed25519_sk_to_curve25519(
  edSk: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
/**
 * Converts an Ed25519 private key to a Curve25519 private key.
 *
 * @param {Uint8Array} edSk - The Ed25519 private key to convert.
 * @param {StringOutputFormat} outputFormat - The desired output format as a string.
 * @returns {string} The corresponding Curve25519 private key as a string.
 */
export function crypto_sign_ed25519_sk_to_curve25519(
  edSk: Uint8Array,
  outputFormat: StringOutputFormat,
): string;
export function crypto_sign_ed25519_sk_to_curve25519(
  edSk: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(crypto_sign_ed25519_sk_to_curve25519, edSk, outputFormat);
}

/**
 * Creates the final signature for a message after a signing process has been initialized.
 *
 * @param {StateAddress} state_address - The state address from a previous sign process.
 * @param {Uint8Array} privateKey - The private key used to complete the signing process.
 * @param {Uint8ArrayOutputFormat | null} [outputFormat=null] - The desired output format. Defaults to `Uint8Array`.
 * @returns {Uint8Array} The final signature for the message.
 */
export function crypto_sign_final_create(
  state_address: StateAddress,
  privateKey: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
/**
 * Creates the final signature for a message after a signing process has been initialized.
 *
 * @param {StateAddress} state_address - The state address from a previous sign process.
 * @param {Uint8Array} privateKey - The private key used to complete the signing process.
 * @param {StringOutputFormat} outputFormat - The desired output format as a string.
 * @returns {string} The final signature for the message as a string.
 */
export function crypto_sign_final_create(
  state_address: StateAddress,
  privateKey: Uint8Array,
  outputFormat: StringOutputFormat,
): string;
export function crypto_sign_final_create(
  state_address: StateAddress,
  privateKey: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(
    crypto_sign_final_create,
    state_address,
    privateKey,
    outputFormat,
  );
}

/**
 * Verifies the final signature of a message after the signing process.
 *
 * @param {StateAddress} state_address - The state address from the signing process.
 * @param {Uint8Array} signature - The signature to verify.
 * @param {Uint8Array} publicKey - The public key used to verify the signature.
 * @returns {boolean} `true` if the signature is valid, `false` otherwise.
 */
export function crypto_sign_final_verify(
  state_address: StateAddress,
  signature: Uint8Array,
  publicKey: Uint8Array,
): boolean {
  return execute(crypto_sign_final_verify, state_address, signature, publicKey);
}

/**
 * Initializes a signing process and returns a state address.
 *
 * @returns {StateAddress} The state address for the signing process.
 */
export function crypto_sign_init(): StateAddress {
  return execute(crypto_sign_init);
}

/**
 * Generates a new key pair for signing (public/private).
 *
 * @param {Uint8ArrayOutputFormat | null} [outputFormat=null] - The desired output format. Defaults to `KeyPair`.
 * @returns {KeyPair} The generated key pair.
 */
export function crypto_sign_keypair(
  outputFormat?: Uint8ArrayOutputFormat | null,
): KeyPair;
export function crypto_sign_keypair(
  outputFormat: StringOutputFormat,
): StringKeyPair;
/**
 * Generates a new key pair for signing (public/private).
 *
 * @param {StringOutputFormat} outputFormat - The desired output format as a string.
 * @returns {StringKeyPair} The generated key pair as a string.
 */
export function crypto_sign_keypair(
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): KeyPair | StringKeyPair {
  return execute(crypto_sign_keypair, outputFormat);
}

/**
 * Verifies and opens a signed message using the public key.
 *
 * @param {string | Uint8Array} signedMessage - The signed message to open.
 * @param {Uint8Array} publicKey - The public key used to verify and open the message.
 * @param {Uint8ArrayOutputFormat | null} [outputFormat=null] - The desired output format. Defaults to `Uint8Array`.
 * @returns {Uint8Array} The original message if valid.
 */
export function crypto_sign_open(
  signedMessage: string | Uint8Array,
  publicKey: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
/**
 * Verifies and opens a signed message using the public key.
 *
 * @param {string | Uint8Array} signedMessage - The signed message to open.
 * @param {Uint8Array} publicKey - The public key used to verify and open the message.
 * @param {StringOutputFormat} outputFormat - The desired output format as a string.
 * @returns {string} The original message if valid.
 */
export function crypto_sign_open(
  signedMessage: string | Uint8Array,
  publicKey: Uint8Array,
  outputFormat: StringOutputFormat,
): string;
export function crypto_sign_open(
  signedMessage: string | Uint8Array,
  publicKey: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(crypto_sign_open, signedMessage, publicKey, outputFormat);
}

/**
 * Generates a new key pair for signing (public/private) using a seed value.
 *
 * @param {Uint8Array} seed - The seed value used to generate the key pair.
 * @param {Uint8ArrayOutputFormat | null} [outputFormat=null] - The desired output format. Defaults to `KeyPair`.
 * @returns {KeyPair} The generated key pair.
 */
export function crypto_sign_seed_keypair(
  seed: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): KeyPair;
/**
 * Generates a new key pair for signing (public/private) using a seed value.
 *
 * @param {Uint8Array} seed - The seed value used to generate the key pair.
 * @param {StringOutputFormat} outputFormat - The desired output format as a string.
 * @returns {StringKeyPair} The generated key pair as a string.
 */
export function crypto_sign_seed_keypair(
  seed: Uint8Array,
  outputFormat: StringOutputFormat,
): StringKeyPair;
export function crypto_sign_seed_keypair(
  seed: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): KeyPair | StringKeyPair {
  return execute(crypto_sign_seed_keypair, seed, outputFormat);
}

/**
 * Updates the signing process with a new chunk of the message.
 *
 * @param {StateAddress} state_address - The state address from the sign process.
 * @param {string | Uint8Array} message_chunk - The chunk of the message to add to the signing process.
 */
export function crypto_sign_update(
  state_address: StateAddress,
  message_chunk: string | Uint8Array,
): void {
  return execute(crypto_sign_update, state_address, message_chunk);
}

/**
 * Verifies a detached signature of a message using the public key.
 *
 * @param {Uint8Array} signature - The detached signature to verify.
 * @param {string | Uint8Array} message - The message whose signature is being verified.
 * @param {Uint8Array} publicKey - The public key used to verify the signature.
 * @returns {boolean} `true` if the signature is valid, `false` otherwise.
 */
export function crypto_sign_verify_detached(
  signature: Uint8Array,
  message: string | Uint8Array,
  publicKey: Uint8Array,
): boolean {
  return execute(crypto_sign_verify_detached, signature, message, publicKey);
}

/**
 * Decodes a base64 encoded string to a `Uint8Array`.
 *
 * @param {string} input - The base64 encoded string to decode.
 * @param {base64_variants} [variant] - The variant of base64 encoding, if applicable.
 * @returns {Uint8Array} The decoded `Uint8Array`.
 */
export function from_base64(
  input: string,
  variant?: Base64Variants,
): Uint8Array {
  return execute(from_base64, input, variant);
}

/**
 * Converts a hexadecimal string to a `Uint8Array`.
 *
 * @param {string} input - The hexadecimal string to convert.
 * @returns {Uint8Array} The converted `Uint8Array`.
 */
export function from_hex(input: string): Uint8Array {
  return execute(from_hex, input);
}

/**
 * Converts a string to a `Uint8Array`.
 *
 * @param {string} str - The string to convert.
 * @returns {Uint8Array} The converted `Uint8Array`.
 */
export function from_string(str: string): Uint8Array {
  return execute(from_string, str);
}

/**
 * Increments the value of each byte in a `Uint8Array` by 1.
 *
 * @param {Uint8Array} bytes - The array of bytes to increment.
 */
export function increment(bytes: Uint8Array): void {
  return execute(increment, bytes);
}

/**
 * Checks if all bytes in the `Uint8Array` are zero.
 *
 * @param {Uint8Array} bytes - The array of bytes to check.
 * @returns {boolean} `true` if all bytes are zero, `false` otherwise.
 */
export function is_zero(bytes: Uint8Array): boolean {
  return execute(is_zero, bytes);
}

/**
 * Compares two `Uint8Array` values.
 *
 * @param {Uint8Array} b1 - The first array to compare.
 * @param {Uint8Array} b2 - The second array to compare.
 * @returns {boolean} `true` if the arrays are equal, `false` otherwise.
 */
export function memcmp(b1: Uint8Array, b2: Uint8Array): boolean {
  return execute(memcmp, b1, b2);
}

/**
 * Zeroes out the contents of the given `Uint8Array` for security purposes.
 *
 * @param {Uint8Array} bytes - The `Uint8Array` whose contents will be zeroed.
 */
export function memzero(bytes: Uint8Array): void {
  return execute(memzero, bytes);
}

/**
 * Returns the available output formats for cryptographic functions.
 *
 * @returns {Array<Uint8ArrayOutputFormat | StringOutputFormat>} An array of supported output formats.
 */
export function output_formats(): Array<
  Uint8ArrayOutputFormat | StringOutputFormat
> {
  return execute(output_formats);
}

/**
 * Pads the given buffer to the specified block size using a standard padding scheme.
 *
 * @param {Uint8Array} buf - The buffer to pad.
 * @param {number} blocksize - The block size to pad to.
 * @returns {Uint8Array} The padded buffer.
 */
export function pad(buf: Uint8Array, blocksize: number): Uint8Array {
  return execute(pad, buf, blocksize);
}

/**
 * Generates a random byte buffer of the specified length.
 *
 * @param {number} length - The length of the random byte buffer to generate.
 * @param {Uint8ArrayOutputFormat | null} [outputFormat=null] - The desired output format. Defaults to `Uint8Array`.
 * @returns {Uint8Array} The generated random byte buffer.
 */
export function randombytes_buf(
  length: number,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
/**
 * Generates a random byte buffer of the specified length.
 *
 * @param {number} length - The length of the random byte buffer to generate.
 * @param {StringOutputFormat} outputFormat - The desired output format as a string.
 * @returns {string} The generated random byte buffer as a string.
 */
export function randombytes_buf(
  length: number,
  outputFormat: StringOutputFormat,
): string;
export function randombytes_buf(
  length: number,
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(randombytes_buf, length, outputFormat);
}

/**
 * Generates a deterministic random byte buffer based on a seed.
 *
 * @param {number} length - The length of the random byte buffer to generate.
 * @param {Uint8Array} seed - The seed used to generate the deterministic random bytes.
 * @param {Uint8ArrayOutputFormat | null} [outputFormat=null] - The desired output format. Defaults to `Uint8Array`.
 * @returns {Uint8Array} The generated deterministic random byte buffer.
 */
export function randombytes_buf_deterministic(
  length: number,
  seed: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
/**
 * Generates a deterministic random byte buffer based on a seed.
 *
 * @param {number} length - The length of the random byte buffer to generate.
 * @param {Uint8Array} seed - The seed used to generate the deterministic random bytes.
 * @param {StringOutputFormat} outputFormat - The desired output format as a string.
 * @returns {string} The generated deterministic random byte buffer as a string.
 */
export function randombytes_buf_deterministic(
  length: number,
  seed: Uint8Array,
  outputFormat: StringOutputFormat,
): string;
export function randombytes_buf_deterministic(
  length: number,
  seed: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(randombytes_buf_deterministic, length, seed, outputFormat);
}

/**
 * Closes the random number generator and frees associated resources.
 */
export function randombytes_close(): void {
  return execute(randombytes_close);
}

/**
 * Returns a random number.
 *
 * @returns {number} A random number.
 */
export function randombytes_random(): number {
  return execute(randombytes_random);
}

/**
 * Stirs the random number generator to ensure it produces unpredictable random data.
 */
export function randombytes_stir(): void {
  return execute(randombytes_stir);
}

/**
 * Returns a random number between 0 (inclusive) and the specified upper bound (exclusive).
 *
 * @param {number} upper_bound - The upper bound (exclusive) for the random number.
 * @returns {number} A random number between 0 and the upper bound.
 */
export function randombytes_uniform(upper_bound: number): number {
  return execute(randombytes_uniform, upper_bound);
}

/**
 * Returns the version string of the Sodium library.
 *
 * @returns {string} The version string of the Sodium library.
 */
export function sodium_version_string(): string {
  return execute(sodium_version_string);
}

/**
 * Returns the list of all symbols available in the Sodium library.
 *
 * @returns {string[]} An array of all symbols.
 */
export function symbols(): string[];
export function symbols(): string[] {
  return execute(symbols);
}

/**
 * Encodes the given input (string or `Uint8Array`) as a base64 string.
 *
 * @param {string | Uint8Array} input - The input to encode.
 * @param {base64_variants} [variant] - The base64 encoding variant (optional).
 * @returns {string} The base64 encoded string.
 */
export function to_base64(
  input: string | Uint8Array,
  variant?: Base64Variants,
): string {
  return execute(to_base64, input, variant);
}

/**
 * Converts the given input (string or `Uint8Array`) to a hexadecimal string.
 *
 * @param {string | Uint8Array} input - The input to convert.
 * @returns {string} The hexadecimal string representation of the input.
 */
export function to_hex(input: string | Uint8Array): string {
  return execute(to_hex, input);
}

/**
 * Converts a `Uint8Array` to a string.
 *
 * @param {Uint8Array} bytes - The `Uint8Array` to convert.
 * @returns {string} The string representation of the `Uint8Array`.
 */
export function to_string(bytes: Uint8Array): string {
  return execute(to_string, bytes);
}

/**
 * Removes padding from the given buffer to restore its original length.
 *
 * @param {Uint8Array} buf - The padded buffer to unpad.
 * @param {number} blocksize - The block size that was used for padding.
 * @returns {Uint8Array} The unpadded buffer.
 */
export function unpad(buf: Uint8Array, blocksize: number): Uint8Array {
  return execute(unpad, buf, blocksize);
}
