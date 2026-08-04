import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Tauri serves the UI from the filesystem, so the frontend is a fully static
  // export. There is no Node server in the shipped app — every privileged
  // operation goes through a Tauri command into the Rust engine.
  output: "export",
  distDir: "out",

  // No image optimisation server exists in a static export.
  images: { unoptimized: true },

  // Pin the workspace root: without it Turbopack walks up and picks up an
  // unrelated package-lock.json from the home directory.
  turbopack: {
    root: __dirname,
  },
};

export default nextConfig;
