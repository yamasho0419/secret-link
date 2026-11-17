import { defineConfig } from "vite";

export default defineConfig({
  // GitHub Pages は https://<ユーザー名>.github.io/<リポジトリ名>/ で配信される。
  // どのパスに置いても動くよう、ファイルの参照を相対パスにする。
  base: "./",
});
