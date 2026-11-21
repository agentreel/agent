#!/usr/bin/env node
/**
 * Rasterize README logo SVGs to PNG (no browser). Run from repo root:
 *   node scripts/render-readme-logo.mjs
 */
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Resvg } from "@resvg/resvg-js";
import sharp from "sharp";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const ASSETS = join(ROOT, ".github/assets");
const DISPLAY_PX = 80;

const VARIANTS = [
  { svg: "agentreel-logo.svg", base: "agentreel-logo-light" },
  { svg: "agentreel-logo-dark.svg", base: "agentreel-logo-dark" },
];

const SCALES = [
  { label: "2x", px: DISPLAY_PX * 2 },
  { label: "3x", px: DISPLAY_PX * 3 },
];

function rasterize(svgPath, outPath, widthPx) {
  const svg = readFileSync(svgPath, "utf8");
  const resvg = new Resvg(svg, {
    fitTo: { mode: "width", value: widthPx },
    background: "transparent",
  });
  const png = resvg.render().asPng();
  writeFileSync(outPath, png);
}

function hexToRgb(hex) {
  const h = hex.replace("#", "");
  return { r: parseInt(h.slice(0, 2), 16), g: parseInt(h.slice(2, 4), 16), b: parseInt(h.slice(4, 6), 16) };
}

function near(a, b, tol = 28) {
  return Math.abs(a.r - b.r) <= tol && Math.abs(a.g - b.g) <= tol && Math.abs(a.b - b.b) <= tol;
}

async function rgbaAt(pngPath, x, y) {
  const { data, info } = await sharp(pngPath).ensureAlpha().raw().toBuffer({ resolveWithObject: true });
  const ix = Math.min(Math.max(Math.round(x), 0), info.width - 1);
  const iy = Math.min(Math.max(Math.round(y), 0), info.height - 1);
  const o = (iy * info.width + ix) * info.channels;
  return {
    r: data[o],
    g: data[o + 1],
    b: data[o + 2],
    a: data[o + 3],
  };
}

async function verifyLight(pngPath, widthPx) {
  const scale = widthPx / 32;
  const pink = await rgbaAt(pngPath, 16 * scale, 5 * scale);
  const hub = await rgbaAt(pngPath, 16 * scale, 16 * scale);
  if (!near(pink, hexToRgb("#ff4fa8"))) {
    throw new Error(`${pngPath}: pink dot not #ff4fa8 at playhead, got rgb(${pink.r},${pink.g},${pink.b})`);
  }
  if (!near(hub, hexToRgb("#1e40ff"))) {
    throw new Error(`${pngPath}: hub not #1e40ff, got rgb(${hub.r},${hub.g},${hub.b})`);
  }
}

async function verifyDark(pngPath, widthPx) {
  const scale = widthPx / 32;
  const ring = await rgbaAt(pngPath, 27 * scale, 16 * scale);
  const hub = await rgbaAt(pngPath, 16 * scale, 16 * scale);
  const corner = await rgbaAt(pngPath, 2, 2);
  if (!near(ring, hexToRgb("#e6e9ec"))) {
    throw new Error(`${pngPath}: dark ring not #e6e9ec, got rgb(${ring.r},${ring.g},${ring.b})`);
  }
  if (!near(hub, hexToRgb("#1e40ff"))) {
    throw new Error(`${pngPath}: hub not #1e40ff, got rgb(${hub.r},${hub.g},${hub.b})`);
  }
  if (corner.a > 8) {
    throw new Error(`${pngPath}: expected transparent corner, alpha=${corner.a}`);
  }
}

for (const { svg, base } of VARIANTS) {
  const svgPath = join(ASSETS, svg);
  for (const { label, px } of SCALES) {
    const suffix = label === "2x" ? "" : `@${label}`;
    const out = join(ASSETS, `${base}${suffix}.png`);
    rasterize(svgPath, out, px);
    if (base.includes("light")) await verifyLight(out, px);
    else await verifyDark(out, px);
    console.log("wrote", out, `${px}x${px}`);
  }
}

console.log("logo PNG verification passed");