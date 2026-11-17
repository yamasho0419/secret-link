import QRCode from "qrcode";
import { DecryptError, decryptMemo, encryptMemo, generatePassword } from "./crypto";

/** リンクの「#」より後ろで、暗号文の前に付ける目印。 */
const HASH_PREFIX = "#m=";
/** これより長いリンクは QR コードが細かくなりすぎて読み取れないので、表示しない。 */
const MAX_QR_LENGTH = 1000;

function $<T extends HTMLElement>(id: string): T {
  const el = document.getElementById(id);
  if (!el) throw new Error(`#${id} が見つかりません`);
  return el as T;
}

const createView = $("create-view");
const createForm = $<HTMLFormElement>("create-form");
const memoInput = $<HTMLTextAreaElement>("memo");
const createPassword = $<HTMLInputElement>("create-password");
const createSubmit = $<HTMLButtonElement>("create-submit");
const created = $("created");
const linkOutput = $<HTMLInputElement>("link");
const qrCanvas = $<HTMLCanvasElement>("qr");
const qrNote = $("qr-note");

const openView = $("open-view");
const openForm = $<HTMLFormElement>("open-form");
const openPassword = $<HTMLInputElement>("open-password");
const openSubmit = $<HTMLButtonElement>("open-submit");
const openError = $("open-error");
const opened = $("opened");
const openedMemo = $("opened-memo");

/** リンクに暗号文が入っていれば「開く画面」、なければ「作る画面」を出す。 */
function showView() {
  const hasMemo = location.hash.startsWith(HASH_PREFIX);
  createView.hidden = hasMemo;
  openView.hidden = !hasMemo;
  // 別のリンクに切り替わったときに、前のメモが残らないようにする。
  openForm.hidden = false;
  opened.hidden = true;
  openedMemo.textContent = "";
  openPassword.value = "";
  openError.hidden = true;
}

$("generate").addEventListener("click", () => {
  createPassword.value = generatePassword();
});

createForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  createSubmit.disabled = true;
  try {
    const token = await encryptMemo(memoInput.value, createPassword.value);
    const url = new URL(location.href);
    url.hash = HASH_PREFIX + token;
    linkOutput.value = url.href;

    const showQr = url.href.length <= MAX_QR_LENGTH;
    if (showQr) await QRCode.toCanvas(qrCanvas, url.href, { width: 240, margin: 2 });
    qrCanvas.hidden = !showQr;
    qrNote.hidden = showQr;
    created.hidden = false;
    created.scrollIntoView({ behavior: "smooth", block: "nearest" });
  } finally {
    createSubmit.disabled = false;
  }
});

// メモやパスワードを直したら、古いリンクを消す（古い内容のリンクを誤って送らないため）。
for (const input of [memoInput, createPassword]) {
  input.addEventListener("input", () => {
    created.hidden = true;
  });
}

openForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  openSubmit.disabled = true;
  openError.hidden = true;
  try {
    const token = location.hash.slice(HASH_PREFIX.length);
    const memo = await decryptMemo(token, openPassword.value);
    // textContent で入れるので、メモに HTML が書かれていても文字として表示される。
    openedMemo.textContent = memo;
    opened.hidden = false;
    openForm.hidden = true;
  } catch (error) {
    if (!(error instanceof DecryptError)) throw error;
    openError.textContent = error.message;
    openError.hidden = false;
  } finally {
    openPassword.value = "";
    openSubmit.disabled = false;
  }
});

function copyButton(button: HTMLElement, getText: () => string) {
  const label = button.textContent;
  button.addEventListener("click", async () => {
    await navigator.clipboard.writeText(getText());
    button.textContent = "コピーしました";
    setTimeout(() => (button.textContent = label), 1500);
  });
}
copyButton($("copy-link"), () => linkOutput.value);
copyButton($("copy-memo"), () => openedMemo.textContent ?? "");

// 暗号機能は https（または localhost）で開いたときしか使えない。
if (!globalThis.crypto?.subtle) {
  $("unsupported").hidden = false;
} else {
  window.addEventListener("hashchange", showView);
  showView();
}
