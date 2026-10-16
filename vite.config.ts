import { defineConfig } from "vite";

// Tauri serves the built assets from dist/ and expects a fixed dev port.
export default defineConfig({
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    watch: {
      // src-tauri is Rust; Vite has no business watching it.
      ignored: ["**/src-tauri/**"],
    },
  },
  build: {
    // Vite 8 minifies with Oxc by default; naming esbuild here would require
    // it as a separate dependency for no benefit on a bundle this small.
    sourcemap: false,
    outDir: "dist",
  },
});
