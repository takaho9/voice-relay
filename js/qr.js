// QR コードのモジュール配列を作る（DOM 非依存。ブラウザと CLI で共用）。
import { qrcode } from '../vendor/qrcode-generator/qrcode.js';

/**
 * @param {string} text ASCII（URL）を想定
 * @returns {{ size: number, isDark: (row: number, col: number) => boolean }}
 */
export function qrMatrix(text) {
  const qr = qrcode(0, 'M'); // 0 = 型番を自動選択
  qr.addData(text, 'Byte');
  qr.make();
  return { size: qr.getModuleCount(), isDark: (r, c) => qr.isDark(r, c) };
}
