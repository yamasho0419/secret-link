import { describe, expect, it } from "vitest";
import { DecryptError, decryptMemo, encryptMemo, generatePassword } from "./crypto";

const PASSWORD = "correct horse battery staple";

/** リンクの文字列の i 番目のバイトを1ビットだけ書き換える。 */
function flipBit(token: string, index: number): string {
  const bytes = Buffer.from(token, "base64url");
  bytes[index] ^= 1;
  return bytes.toString("base64url");
}

describe("encryptMemo / decryptMemo", () => {
  it("正しいパスワードなら元のメモに戻る", async () => {
    const memo = "Wi-Fi のパスワードは abc-123 です。\n2行目 🔑";
    const token = await encryptMemo(memo, PASSWORD);
    expect(await decryptMemo(token, PASSWORD)).toBe(memo);
  });

  it("空のメモも扱える", async () => {
    const token = await encryptMemo("", PASSWORD);
    expect(await decryptMemo(token, PASSWORD)).toBe("");
  });

  it("パスワードが違うと復号できない", async () => {
    const token = await encryptMemo("秘密", PASSWORD);
    await expect(decryptMemo(token, PASSWORD + "x")).rejects.toBeInstanceOf(DecryptError);
  });

  it("同じメモとパスワードでも、暗号文は毎回変わる", async () => {
    const a = await encryptMemo("秘密", PASSWORD);
    const b = await encryptMemo("秘密", PASSWORD);
    expect(a).not.toBe(b);
  });

  it("暗号文にメモの文字列がそのまま含まれない", async () => {
    const token = await encryptMemo("plaintext-marker", PASSWORD);
    expect(Buffer.from(token, "base64url").toString("latin1")).not.toContain("plaintext-marker");
  });

  it("URL に入れても壊れない文字だけでできている", async () => {
    const token = await encryptMemo("秘密".repeat(50), PASSWORD);
    expect(token).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it("全角で入力したパスワードでも、半角と同じように復号できる", async () => {
    const token = await encryptMemo("秘密", "abc123");
    expect(await decryptMemo(token, "ａｂｃ１２３")).toBe("秘密");
  });

  // どの部分を1ビット書き換えても、正しいパスワードで復号できなくなることを確かめる。
  it.each([
    ["バージョン", 0],
    ["ソルト", 1],
    ["IV", 17],
    ["暗号化されたメモ", 29],
    ["改ざん検知用タグ（末尾）", -1],
  ])("%s を書き換えると復号できない", async (_part, index) => {
    const token = await encryptMemo("秘密のメモ", PASSWORD);
    const length = Buffer.from(token, "base64url").length;
    const tampered = flipBit(token, index < 0 ? length + index : index);
    await expect(decryptMemo(tampered, PASSWORD)).rejects.toBeInstanceOf(DecryptError);
  });

  it.each([
    ["空", ""],
    ["使えない文字を含む", "abc$%^"],
    ["短すぎる", "AQID"],
  ])("形式が正しくないデータ（%s）は拒否する", async (_name, token) => {
    await expect(decryptMemo(token, PASSWORD)).rejects.toBeInstanceOf(DecryptError);
  });
});

describe("generatePassword", () => {
  it("指定した長さで、見間違えやすい文字を含まない", () => {
    const password = generatePassword(200);
    expect(password).toHaveLength(200);
    expect(password).toMatch(/^[a-km-zA-HJ-NP-Z2-9]+$/);
  });

  it("毎回違う値になる", () => {
    expect(generatePassword()).not.toBe(generatePassword());
  });
});
