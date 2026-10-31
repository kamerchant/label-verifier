#!/usr/bin/env bash
set -euo pipefail

# Rebuilds app/static/vendor from npm packages and compiles Tailwind CSS.
# Run after changing a template's CSS classes or a library version, then commit app/static/vendor.
# The deployed app needs none of this: the built files are served from app/static/vendor.
cd "$(dirname "$0")/.."

npm ci --ignore-scripts --no-audit --no-fund

vendor=app/static/vendor
rm -rf "$vendor"
mkdir -p "$vendor/tesseract"

npx tailwindcss -c tailwind.config.js -i src/tailwind.css -o "$vendor/tailwind.css" --minify

cp node_modules/html5-qrcode/html5-qrcode.min.js "$vendor/"
cp node_modules/qrcodejs/qrcode.min.js "$vendor/"

# Tesseract OCR: main script, worker, the two English-capable core builds it can select, and the language data.
cp node_modules/tesseract.js/dist/tesseract.min.js "$vendor/tesseract/"
cp node_modules/tesseract.js/dist/worker.min.js "$vendor/tesseract/"
cp node_modules/tesseract.js-core/tesseract-core-lstm.wasm.js "$vendor/tesseract/"
cp node_modules/tesseract.js-core/tesseract-core-simd-lstm.wasm.js "$vendor/tesseract/"
cp node_modules/@tesseract.js-data/eng/4.0.0_best_int/eng.traineddata.gz "$vendor/tesseract/"

echo "Built $vendor:"
du -sh "$vendor"/* "$vendor"/tesseract/*
