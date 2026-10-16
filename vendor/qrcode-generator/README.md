# qrcode-generator（同梱ライブラリ）

- ファイル: `qrcode.js`（無改変。元のファイル名は `qrcode.mjs`。どの静的ホスティングでも JavaScript の MIME タイプで配信されるよう拡張子だけ変更）
- 出典: npm パッケージ [`qrcode-generator@2.0.4`](https://www.npmjs.com/package/qrcode-generator) の `dist/qrcode.mjs`
  - リポジトリ: https://github.com/kazuhikoarase/qrcode-generator
  - tarball integrity: `sha512-mZSiP6RnbHl4xL2Ap5HfkjLnmxfKcPWpWe/c+5XxCuetEenqmNFf1FH/ftXPCtFG5/TDobjsjz6sSNL0Sr8Z9g==`
  - `qrcode.js` の SHA-256: `ea91d7118a5395289170da848b7c6758b996163bfbccf312591ab65a4911b7c0`
- 作者: Kazuhiko Arase
- ライセンス: MIT（全文は同じディレクトリの `LICENSE`）

照合方法:

```sh
npm pack qrcode-generator@2.0.4
tar -xzf qrcode-generator-2.0.4.tgz
sha256sum package/dist/qrcode.mjs vendor/qrcode-generator/qrcode.js
```

"QR Code" は株式会社デンソーウェーブの登録商標です。
