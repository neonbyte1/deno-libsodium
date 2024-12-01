import * as sodium from "npm:libsodium-wrappers@0.7.15";

export enum Base64Variants {
  ORIGINAL,
  ORIGINAL_NO_PADDING,
  URLSAFE,
  URLSAFE_NO_PADDING,
}

export type Uint8ArrayOutputFormat = "uint8array";
export type StringOutputFormat = "text" | "hex" | "base64";
export type KeyType = "curve25519" | "ed25519" | "x25519";

interface GenericCryptoBox<T extends Uint8Array | string> {
  ciphertext: T;
  mac: T;
}
export type CryptoBox = GenericCryptoBox<Uint8Array>;
export type StringCryptoBox = GenericCryptoBox<string>;

interface GenericSecretBox<T extends Uint8Array | string> {
  cipher: T;
  mac: T;
}
export type SecretBox = GenericSecretBox<Uint8Array>;
export type StringSecretBox = GenericSecretBox<string>;

interface GenericCryptoKX<T extends Uint8Array | string> {
  ciphertext: T;
  sjaredRx: T;
  sharedTx: T;
}
export type CryptoKX = GenericCryptoKX<Uint8Array>;
export type StringCryptoKX = GenericCryptoKX<string>;

interface GenericKeyPair<T extends Uint8Array | string> {
  keyType: KeyType;
  privateKey: T;
  publicKey: T;
}
export type KeyPair = GenericKeyPair<Uint8Array>;
export type StringKeyPair = GenericKeyPair<string>;

interface GenericTag<T extends Uint8Array | string> {
  message: T;
  tag: number;
}
export type MessageTag = GenericTag<Uint8Array>;
export type StringMessageTag = GenericTag<string>;

export interface StateAddress {
  name: string;
}

export let crypto_aead_chacha20poly1305_ABYTES: number = -1;
export let crypto_aead_chacha20poly1305_ietf_ABYTES: number = -1;
export let crypto_aead_chacha20poly1305_IETF_ABYTES: number = -1;
export let crypto_aead_chacha20poly1305_ietf_KEYBYTES: number = -1;
export let crypto_aead_chacha20poly1305_IETF_KEYBYTES: number = -1;
export let crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX: number = -1;
export let crypto_aead_chacha20poly1305_IETF_MESSAGEBYTES_MAX: number = -1;
export let crypto_aead_chacha20poly1305_ietf_NPUBBYTES: number = -1;
export let crypto_aead_chacha20poly1305_IETF_NPUBBYTES: number = -1;
export let crypto_aead_chacha20poly1305_ietf_NSECBYTES: number = -1;
export let crypto_aead_chacha20poly1305_IETF_NSECBYTES: number = -1;
export let crypto_aead_chacha20poly1305_KEYBYTES: number = -1;
export let crypto_aead_chacha20poly1305_MESSAGEBYTES_MAX: number = -1;
export let crypto_aead_chacha20poly1305_NPUBBYTES: number = -1;
export let crypto_aead_chacha20poly1305_NSECBYTES: number = -1;
export let crypto_aead_xchacha20poly1305_ietf_ABYTES: number = -1;
export let crypto_aead_xchacha20poly1305_IETF_ABYTES: number = -1;
export let crypto_aead_xchacha20poly1305_ietf_KEYBYTES: number = -1;
export let crypto_aead_xchacha20poly1305_IETF_KEYBYTES: number = -1;
export let crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX: number = -1;
export let crypto_aead_xchacha20poly1305_IETF_MESSAGEBYTES_MAX: number = -1;
export let crypto_aead_xchacha20poly1305_ietf_NPUBBYTES: number = -1;
export let crypto_aead_xchacha20poly1305_IETF_NPUBBYTES: number = -1;
export let crypto_aead_xchacha20poly1305_ietf_NSECBYTES: number = -1;
export let crypto_aead_xchacha20poly1305_IETF_NSECBYTES: number = -1;
export let crypto_aead_aegis128l_ABYTES: number = -1;
export let crypto_aead_aegis128l_KEYBYTES: number = -1;
export let crypto_aead_aegis128l_MESSAGEBYTES_MAX: number = -1;
export let crypto_aead_aegis128l_NPUBBYTES: number = -1;
export let crypto_aead_aegis128l_NSECBYTES: number = -1;
export let crypto_aead_aegis256_ABYTES: number = -1;
export let crypto_aead_aegis256_KEYBYTES: number = -1;
export let crypto_aead_aegis256_MESSAGEBYTES_MAX: number = -1;
export let crypto_aead_aegis256_NPUBBYTES: number = -1;
export let crypto_aead_aegis256_NSECBYTES: number = -1;
export let crypto_auth_BYTES: number = -1;
export let crypto_auth_KEYBYTES: number = -1;
export let crypto_box_BEFORENMBYTES: number = -1;
export let crypto_box_MACBYTES: number = -1;
export let crypto_box_MESSAGEBYTES_MAX: number = -1;
export let crypto_box_NONCEBYTES: number = -1;
export let crypto_box_PUBLICKEYBYTES: number = -1;
export let crypto_box_SEALBYTES: number = -1;
export let crypto_box_SECRETKEYBYTES: number = -1;
export let crypto_box_SEEDBYTES: number = -1;
export let crypto_generichash_BYTES: number = -1;
export let crypto_generichash_BYTES_MAX: number = -1;
export let crypto_generichash_BYTES_MIN: number = -1;
export let crypto_generichash_KEYBYTES: number = -1;
export let crypto_generichash_KEYBYTES_MAX: number = -1;
export let crypto_generichash_KEYBYTES_MIN: number = -1;
export let crypto_hash_BYTES: number = -1;
export let crypto_kdf_BYTES_MAX: number = -1;
export let crypto_kdf_BYTES_MIN: number = -1;
export let crypto_kdf_CONTEXTBYTES: number = -1;
export let crypto_kdf_KEYBYTES: number = -1;
export let crypto_kx_PUBLICKEYBYTES: number = -1;
export let crypto_kx_SECRETKEYBYTES: number = -1;
export let crypto_kx_SEEDBYTES: number = -1;
export let crypto_kx_SESSIONKEYBYTES: number = -1;
export let crypto_pwhash_ALG_ARGON2I13: number = -1;
export let crypto_pwhash_ALG_ARGON2ID13: number = -1;
export let crypto_pwhash_ALG_DEFAULT: number = -1;
export let crypto_pwhash_BYTES_MAX: number = -1;
export let crypto_pwhash_BYTES_MIN: number = -1;
export let crypto_pwhash_MEMLIMIT_INTERACTIVE: number = -1;
export let crypto_pwhash_MEMLIMIT_MAX: number = -1;
export let crypto_pwhash_MEMLIMIT_MIN: number = -1;
export let crypto_pwhash_MEMLIMIT_MODERATE: number = -1;
export let crypto_pwhash_MEMLIMIT_SENSITIVE: number = -1;
export let crypto_pwhash_OPSLIMIT_INTERACTIVE: number = -1;
export let crypto_pwhash_OPSLIMIT_MAX: number = -1;
export let crypto_pwhash_OPSLIMIT_MIN: number = -1;
export let crypto_pwhash_OPSLIMIT_MODERATE: number = -1;
export let crypto_pwhash_OPSLIMIT_SENSITIVE: number = -1;
export let crypto_pwhash_PASSWD_MAX: number = -1;
export let crypto_pwhash_PASSWD_MIN: number = -1;
export let crypto_pwhash_SALTBYTES: number = -1;
export let crypto_pwhash_STRBYTES: number = -1;
export let crypto_pwhash_STRPREFIX: string = "";
export let crypto_scalarmult_BYTES: number = -1;
export let crypto_scalarmult_SCALARBYTES: number = -1;
export let crypto_secretbox_KEYBYTES: number = -1;
export let crypto_secretbox_MACBYTES: number = -1;
export let crypto_secretbox_MESSAGEBYTES_MAX: number = -1;
export let crypto_secretbox_NONCEBYTES: number = -1;
export let crypto_secretstream_xchacha20poly1305_ABYTES: number = -1;
export let crypto_secretstream_xchacha20poly1305_HEADERBYTES: number = -1;
export let crypto_secretstream_xchacha20poly1305_KEYBYTES: number = -1;
export let crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX: number = -1;
export let crypto_secretstream_xchacha20poly1305_TAG_FINAL: number = -1;
export let crypto_secretstream_xchacha20poly1305_TAG_MESSAGE: number = -1;
export let crypto_secretstream_xchacha20poly1305_TAG_PUSH: number = -1;
export let crypto_secretstream_xchacha20poly1305_TAG_REKEY: number = -1;
export let crypto_shorthash_BYTES: number = -1;
export let crypto_shorthash_KEYBYTES: number = -1;
export let crypto_sign_BYTES: number = -1;
export let crypto_sign_MESSAGEBYTES_MAX: number = -1;
export let crypto_sign_PUBLICKEYBYTES: number = -1;
export let crypto_sign_SECRETKEYBYTES: number = -1;
export let crypto_sign_SEEDBYTES: number = -1;
export let SODIUM_LIBRARY_VERSION_MAJOR: number = -1;
export let SODIUM_LIBRARY_VERSION_MINOR: number = -1;
export let SODIUM_VERSION_STRING: string = "";

export async function sodium_init(): Promise<void> {
  await sodium.default.libsodium.ready;

  //crypto_secretbox_KEYBYTES = sodium.default.crypto_secretbox_KEYBYTES;

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

export function add(a: Uint8Array, b: Uint8Array): void {
  return execute(add, a, b);
}

export function compare(b1: Uint8Array, b2: Uint8Array): number {
  return execute(compare, b1, b2);
}

export function crypto_aead_chacha20poly1305_decrypt(
  secret_nonce: string | Uint8Array | null,
  ciphertext: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
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

export function crypto_aead_chacha20poly1305_decrypt_detached(
  secret_nonce: string | Uint8Array | null,
  ciphertext: string | Uint8Array,
  mac: Uint8Array,
  additional_data: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
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

export function crypto_aead_chacha20poly1305_encrypt(
  message: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  secret_nonce: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
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

export function crypto_aead_chacha20poly1305_encrypt_detached(
  message: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  secret_nonce: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): CryptoBox;
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

export function crypto_aead_chacha20poly1305_ietf_decrypt(
  secret_nonce: string | Uint8Array | null,
  ciphertext: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
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

export function crypto_aead_chacha20poly1305_ietf_decrypt_detached(
  secret_nonce: string | Uint8Array | null,
  ciphertext: string | Uint8Array,
  mac: Uint8Array,
  additional_data: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
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

export function crypto_aead_chacha20poly1305_ietf_encrypt(
  message: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  secret_nonce: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
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

export function crypto_aead_chacha20poly1305_ietf_encrypt_detached(
  message: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  secret_nonce: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): CryptoBox;
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

export function crypto_aead_chacha20poly1305_ietf_keygen(
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
export function crypto_aead_chacha20poly1305_ietf_keygen(
  outputFormat: StringOutputFormat,
): string;
export function crypto_aead_chacha20poly1305_ietf_keygen(
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(crypto_aead_chacha20poly1305_ietf_keygen, outputFormat);
}

export function crypto_aead_chacha20poly1305_keygen(
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
export function crypto_aead_chacha20poly1305_keygen(
  outputFormat: StringOutputFormat,
): string;
export function crypto_aead_chacha20poly1305_keygen(
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(crypto_aead_chacha20poly1305_keygen, outputFormat);
}

export function crypto_aead_xchacha20poly1305_ietf_decrypt(
  secret_nonce: string | Uint8Array | null,
  ciphertext: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
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

export function crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
  secret_nonce: string | Uint8Array | null,
  ciphertext: string | Uint8Array,
  mac: Uint8Array,
  additional_data: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
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

export function crypto_aead_xchacha20poly1305_ietf_encrypt(
  message: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  secret_nonce: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
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

export function crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
  message: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  secret_nonce: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): CryptoBox;
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

export function crypto_aead_xchacha20poly1305_ietf_keygen(
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
export function crypto_aead_xchacha20poly1305_ietf_keygen(
  outputFormat: StringOutputFormat,
): string;
export function crypto_aead_xchacha20poly1305_ietf_keygen(
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(crypto_aead_xchacha20poly1305_ietf_keygen, outputFormat);
}

export function crypto_aead_aegis128l_decrypt(
  secret_nonce: string | Uint8Array | null,
  ciphertext: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
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

export function crypto_aead_aegis128l_decrypt_detached(
  secret_nonce: string | Uint8Array | null,
  ciphertext: string | Uint8Array,
  mac: Uint8Array,
  additional_data: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
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

export function crypto_aead_aegis128l_encrypt(
  message: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  secret_nonce: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
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

export function crypto_aead_aegis128l_encrypt_detached(
  message: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  secret_nonce: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): CryptoBox;
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

export function crypto_aead_aegis128l_keygen(
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
export function crypto_aead_aegis128l_keygen(
  outputFormat: StringOutputFormat,
): string;
export function crypto_aead_aegis128l_keygen(
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(crypto_aead_aegis128l_keygen, outputFormat);
}

export function crypto_aead_aegis256_decrypt(
  secret_nonce: string | Uint8Array | null,
  ciphertext: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
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

export function crypto_aead_aegis256_decrypt_detached(
  secret_nonce: string | Uint8Array | null,
  ciphertext: string | Uint8Array,
  mac: Uint8Array,
  additional_data: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
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

export function crypto_aead_aegis256_encrypt(
  message: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  secret_nonce: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
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

export function crypto_aead_aegis256_encrypt_detached(
  message: string | Uint8Array,
  additional_data: string | Uint8Array | null,
  secret_nonce: string | Uint8Array | null,
  public_nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): CryptoBox;
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

export function crypto_aead_aegis256_keygen(
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
export function crypto_aead_aegis256_keygen(
  outputFormat: StringOutputFormat,
): string;
export function crypto_aead_aegis256_keygen(
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(crypto_aead_aegis256_keygen, outputFormat);
}

export function crypto_auth(
  message: string | Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
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

export function crypto_auth_keygen(
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
export function crypto_auth_keygen(outputFormat: StringOutputFormat): string;
export function crypto_auth_keygen(
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(crypto_auth_keygen, outputFormat);
}

export function crypto_auth_verify(
  tag: Uint8Array,
  message: string | Uint8Array,
  key: Uint8Array,
): boolean {
  return execute(crypto_auth_verify, tag, message, key);
}

export function crypto_box_beforenm(
  publicKey: Uint8Array,
  privateKey: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
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

export function crypto_box_detached(
  message: string | Uint8Array,
  nonce: Uint8Array,
  publicKey: Uint8Array,
  privateKey: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): CryptoBox;
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

export function crypto_box_easy(
  message: string | Uint8Array,
  nonce: Uint8Array,
  publicKey: Uint8Array,
  privateKey: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
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

export function crypto_box_easy_afternm(
  message: string | Uint8Array,
  nonce: Uint8Array,
  sharedKey: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
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

export function crypto_box_keypair(
  outputFormat?: Uint8ArrayOutputFormat | null,
): KeyPair;
export function crypto_box_keypair(
  outputFormat: StringOutputFormat,
): StringKeyPair;
export function crypto_box_keypair(
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): KeyPair | StringKeyPair {
  return execute(crypto_box_keypair, outputFormat);
}

export function crypto_box_open_detached(
  ciphertext: string | Uint8Array,
  mac: Uint8Array,
  nonce: Uint8Array,
  publicKey: Uint8Array,
  privateKey: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
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

export function crypto_box_open_easy(
  ciphertext: string | Uint8Array,
  nonce: Uint8Array,
  publicKey: Uint8Array,
  privateKey: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
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

export function crypto_box_open_easy_afternm(
  ciphertext: string | Uint8Array,
  nonce: Uint8Array,
  sharedKey: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
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

export function crypto_box_seal(
  message: string | Uint8Array,
  publicKey: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
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

export function crypto_box_seal_open(
  ciphertext: string | Uint8Array,
  publicKey: Uint8Array,
  privateKey: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
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

export function crypto_box_seed_keypair(
  seed: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): KeyPair;
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

export function crypto_generichash(
  hash_length: number,
  message: string | Uint8Array,
  key?: string | Uint8Array | null,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
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

export function crypto_generichash_init(
  key: string | Uint8Array | null,
  hash_length: number,
): StateAddress {
  return execute(crypto_generichash_init, key, hash_length);
}

export function crypto_generichash_keygen(
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
export function crypto_generichash_keygen(
  outputFormat: StringOutputFormat,
): string;
export function crypto_generichash_keygen(
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(crypto_generichash_keygen, outputFormat);
}

export function crypto_generichash_update(
  state_address: StateAddress,
  message_chunk: string | Uint8Array,
): void {
  return execute(crypto_generichash_update, state_address, message_chunk);
}

export function crypto_hash(
  message: string | Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
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

export function crypto_kdf_derive_from_key(
  subkey_len: number,
  subkey_id: number,
  ctx: string,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
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

export function crypto_kdf_keygen(
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
export function crypto_kdf_keygen(outputFormat: StringOutputFormat): string;
export function crypto_kdf_keygen(
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(crypto_kdf_keygen, outputFormat);
}

export function crypto_kx_client_session_keys(
  clientPublicKey: Uint8Array,
  clientSecretKey: Uint8Array,
  serverPublicKey: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): CryptoKX;
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

export function crypto_kx_keypair(
  outputFormat?: Uint8ArrayOutputFormat | null,
): KeyPair;
export function crypto_kx_keypair(
  outputFormat: StringOutputFormat,
): StringKeyPair;
export function crypto_kx_keypair(
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): KeyPair | StringKeyPair {
  return execute(crypto_kx_keypair, outputFormat);
}

export function crypto_kx_seed_keypair(
  seed: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): KeyPair;
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

export function crypto_kx_server_session_keys(
  serverPublicKey: Uint8Array,
  serverSecretKey: Uint8Array,
  clientPublicKey: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): CryptoKX;
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

export function crypto_pwhash(
  keyLength: number,
  password: string | Uint8Array,
  salt: Uint8Array,
  opsLimit: number,
  memLimit: number,
  algorithm: number,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
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

export function crypto_pwhash_str(
  password: string | Uint8Array,
  opsLimit: number,
  memLimit: number,
): string {
  return execute(crypto_pwhash_str, password, opsLimit, memLimit);
}

export function crypto_pwhash_str_verify(
  hashed_password: string,
  password: string | Uint8Array,
): boolean {
  return execute(crypto_pwhash_str_verify, hashed_password, password);
}

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

export function crypto_scalarmult(
  privateKey: Uint8Array,
  publicKey: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
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

export function crypto_scalarmult_base(
  privateKey: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
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

export function crypto_secretbox_detached(
  message: string | Uint8Array,
  nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): SecretBox;
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

export function crypto_secretbox_easy(
  message: string | Uint8Array,
  nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
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

export function crypto_secretbox_keygen(
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
export function crypto_secretbox_keygen(
  outputFormat: StringOutputFormat,
): string;
export function crypto_secretbox_keygen(
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(crypto_secretbox_keygen, outputFormat);
}

export function crypto_secretbox_open_detached(
  ciphertext: string | Uint8Array,
  mac: Uint8Array,
  nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
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

export function crypto_secretbox_open_easy(
  ciphertext: string | Uint8Array,
  nonce: Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
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

export function crypto_secretstream_xchacha20poly1305_init_pull(
  header: Uint8Array,
  key: Uint8Array,
): StateAddress {
  return execute(crypto_secretstream_xchacha20poly1305_init_pull, header, key);
}

export function crypto_secretstream_xchacha20poly1305_init_push(
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): { state: StateAddress; header: Uint8Array };
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

export function crypto_secretstream_xchacha20poly1305_keygen(
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
export function crypto_secretstream_xchacha20poly1305_keygen(
  outputFormat: StringOutputFormat,
): string;
export function crypto_secretstream_xchacha20poly1305_keygen(
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(crypto_secretstream_xchacha20poly1305_keygen, outputFormat);
}

export function crypto_secretstream_xchacha20poly1305_pull(
  state_address: StateAddress,
  cipher: string | Uint8Array,
  ad?: string | Uint8Array | null,
  outputFormat?: Uint8ArrayOutputFormat | null,
): MessageTag;
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

export function crypto_secretstream_xchacha20poly1305_push(
  state_address: StateAddress,
  message_chunk: string | Uint8Array,
  ad: string | Uint8Array | null,
  tag: number,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
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

export function crypto_secretstream_xchacha20poly1305_rekey(
  state_address: StateAddress,
): true {
  return execute(crypto_secretstream_xchacha20poly1305_rekey, state_address);
}

export function crypto_shorthash(
  message: string | Uint8Array,
  key: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
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

export function crypto_shorthash_keygen(
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
export function crypto_shorthash_keygen(
  outputFormat: StringOutputFormat,
): string;
export function crypto_shorthash_keygen(
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): Uint8Array | string {
  return execute(crypto_shorthash_keygen, outputFormat);
}

export function crypto_sign(
  message: string | Uint8Array,
  privateKey: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
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

export function crypto_sign_detached(
  message: string | Uint8Array,
  privateKey: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
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

export function crypto_sign_ed25519_pk_to_curve25519(
  edPk: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
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

export function crypto_sign_ed25519_sk_to_curve25519(
  edSk: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
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

export function crypto_sign_final_create(
  state_address: StateAddress,
  privateKey: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
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

export function crypto_sign_final_verify(
  state_address: StateAddress,
  signature: Uint8Array,
  publicKey: Uint8Array,
): boolean {
  return execute(crypto_sign_final_verify, state_address, signature, publicKey);
}

export function crypto_sign_init(): StateAddress {
  return execute(crypto_sign_init);
}

export function crypto_sign_keypair(
  outputFormat?: Uint8ArrayOutputFormat | null,
): KeyPair;
export function crypto_sign_keypair(
  outputFormat: StringOutputFormat,
): StringKeyPair;
export function crypto_sign_keypair(
  outputFormat?: Uint8ArrayOutputFormat | StringOutputFormat | null,
): KeyPair | StringKeyPair {
  return execute(crypto_sign_keypair, outputFormat);
}

export function crypto_sign_open(
  signedMessage: string | Uint8Array,
  publicKey: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
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

export function crypto_sign_seed_keypair(
  seed: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): KeyPair;
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

export function crypto_sign_update(
  state_address: StateAddress,
  message_chunk: string | Uint8Array,
): void {
  return execute(crypto_sign_update, state_address, message_chunk);
}

export function crypto_sign_verify_detached(
  signature: Uint8Array,
  message: string | Uint8Array,
  publicKey: Uint8Array,
): boolean {
  return execute(crypto_sign_verify_detached, signature, message, publicKey);
}

export function from_base64(
  input: string,
  variant?: Base64Variants,
): Uint8Array {
  return execute(from_base64, input, variant);
}

export function from_hex(input: string): Uint8Array {
  return execute(from_hex, input);
}

export function from_string(str: string): Uint8Array {
  return execute(from_string, str);
}

export function increment(bytes: Uint8Array): void {
  return execute(increment, bytes);
}

export function is_zero(bytes: Uint8Array): boolean {
  return execute(is_zero, bytes);
}

export function memcmp(b1: Uint8Array, b2: Uint8Array): boolean {
  return execute(memcmp, b1, b2);
}

export function memzero(bytes: Uint8Array): void {
  return execute(memzero, bytes);
}

export function output_formats(): Array<
  Uint8ArrayOutputFormat | StringOutputFormat
> {
  return execute(output_formats);
}

export function pad(buf: Uint8Array, blocksize: number): Uint8Array {
  return execute(pad, buf, blocksize);
}

export function randombytes_buf(
  length: number,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
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

export function randombytes_buf_deterministic(
  length: number,
  seed: Uint8Array,
  outputFormat?: Uint8ArrayOutputFormat | null,
): Uint8Array;
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

export function randombytes_close(): void {
  return execute(randombytes_close);
}

export function randombytes_random(): number {
  return execute(randombytes_random);
}

export function randombytes_stir(): void {
  return execute(randombytes_stir);
}

export function randombytes_uniform(upper_bound: number): number {
  return execute(randombytes_uniform, upper_bound);
}

export function sodium_version_string(): string {
  return execute(sodium_version_string);
}

export function symbols(): string[] {
  return execute(symbols);
}

export function to_base64(
  input: string | Uint8Array,
  variant?: Base64Variants,
): string {
  return execute(to_base64, input, variant);
}

export function to_hex(input: string | Uint8Array): string {
  return execute(to_hex, input);
}

export function to_string(bytes: Uint8Array): string {
  return execute(to_string, bytes);
}

export function unpad(buf: Uint8Array, blocksize: number): Uint8Array {
  return execute(unpad, buf, blocksize);
}
