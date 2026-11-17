// メモの暗号化と復号。
//
// 暗号のアルゴリズムは自作せず、ブラウザ標準の Web Crypto API に任せる。
// このファイルで決めているのは「どの方式を、どの設定で、どう組み合わせるか」だけ。
//
// 暗号文（リンクに入れるデータ）の並び：
//
//   [バージョン 1バイト][ソルト 16バイト][IV 12バイト][暗号化されたメモ + 改ざん検知用タグ]
//
// これを URL に入れられる文字（base64url）に変換する。

/** データ形式のバージョン。方式や設定を変えるときは番号を上げる。 */
const VERSION = 1;
const SALT_BYTES = 16;
const IV_BYTES = 12;
const HEADER_BYTES = 1 + SALT_BYTES + IV_BYTES;
/** AES-GCM が末尾に付ける、改ざん検知用タグの長さ。 */
const TAG_BYTES = 16;

/**
 * パスワードから鍵を作るときの計算の繰り返し回数。
 * わざと時間をかけて、パスワードの総当たりを1回ごとに遅くする。
 * OWASP が PBKDF2-HMAC-SHA256 に推奨している値（60万回）を使う。
 */
const PBKDF2_ITERATIONS = 600_000;

/** パスワード自動生成に使う文字。見間違えやすい 0 O 1 l I は除いてある。 */
const PASSWORD_ALPHABET = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";

/** 復号できなかったことを表すエラー。原因（パスワード違い・改ざん・破損）は区別しない。 */
export class DecryptError extends Error {
  constructor() {
    super("パスワードが違うか、リンクが壊れています");
    this.name = "DecryptError";
  }
}

/** メモをパスワードで暗号化し、リンクに入れる文字列を返す。 */
export async function encryptMemo(memo: string, password: string): Promise<string> {
  // ソルトと IV は毎回ランダムに作る。同じメモ・同じパスワードでも、結果は毎回変わる。
  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const key = await deriveKey(password, salt);

  const version = new Uint8Array([VERSION]);
  const encrypted = new Uint8Array(
    await crypto.subtle.encrypt(
      // additionalData に入れた値は暗号化されないが、書き換えると復号に失敗する。
      { name: "AES-GCM", iv, additionalData: version },
      key,
      new TextEncoder().encode(memo),
    ),
  );

  const out = new Uint8Array(HEADER_BYTES + encrypted.length);
  out.set(version, 0);
  out.set(salt, 1);
  out.set(iv, 1 + SALT_BYTES);
  out.set(encrypted, HEADER_BYTES);
  return toBase64Url(out);
}

/**
 * リンクの文字列をパスワードで復号し、メモを返す。
 * パスワードが違う場合も、データが1ビットでも書き換えられている場合も DecryptError になる。
 */
export async function decryptMemo(token: string, password: string): Promise<string> {
  const data = fromBase64Url(token);
  if (data === null || data.length < HEADER_BYTES + TAG_BYTES || data[0] !== VERSION) {
    throw new DecryptError();
  }
  const version = data.subarray(0, 1);
  const salt = data.subarray(1, 1 + SALT_BYTES);
  const iv = data.subarray(1 + SALT_BYTES, HEADER_BYTES);
  const encrypted = data.subarray(HEADER_BYTES);

  const key = await deriveKey(password, salt);
  try {
    const plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv, additionalData: version },
      key,
      encrypted,
    );
    return new TextDecoder("utf-8", { fatal: true }).decode(plain);
  } catch {
    throw new DecryptError();
  }
}

/** 推測されにくいパスワードを作る（20文字、約116ビットの強さ）。 */
export function generatePassword(length = 20): string {
  const n = PASSWORD_ALPHABET.length;
  // 256 を n で割った余りの分だけ、一部の文字が出やすくなる。
  // それを避けるため、範囲からはみ出た乱数は捨てて引き直す。
  const limit = 256 - (256 % n);
  let out = "";
  while (out.length < length) {
    for (const byte of crypto.getRandomValues(new Uint8Array(length))) {
      if (byte < limit && out.length < length) out += PASSWORD_ALPHABET[byte % n];
    }
  }
  return out;
}

/** パスワードとソルトから、AES-256 の鍵を作る。 */
async function deriveKey(password: string, salt: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
  // 端末や入力方法によって、同じ見た目の文字が別のデータになることがある（全角と半角など）。
  // 別の端末で入力しても同じ鍵になるよう、表記をそろえてから使う。
  const normalized = new TextEncoder().encode(password.normalize("NFKC"));
  const material = await crypto.subtle.importKey("raw", normalized, "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: PBKDF2_ITERATIONS },
    material,
    { name: "AES-GCM", length: 256 },
    false, // 鍵を取り出せない設定にする
    ["encrypt", "decrypt"],
  );
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function fromBase64Url(text: string): Uint8Array<ArrayBuffer> | null {
  if (!/^[A-Za-z0-9_-]+$/.test(text)) return null;
  try {
    const binary = atob(text.replaceAll("-", "+").replaceAll("_", "/"));
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  } catch {
    return null;
  }
}
