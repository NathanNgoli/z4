#!/bin/bash
set -e

VERSION=${1:-"dev"}
OUTPUT_DIR="dist"

mkdir -p $OUTPUT_DIR

TARGETS=(
    "x86_64-linux-gnu"
    "x86_64-linux-musl"
    "aarch64-linux-gnu"
    "aarch64-linux-musl"
    "x86_64-macos"
    "aarch64-macos"
)

echo "Building Z4 $VERSION for all platforms..."

for target in "${TARGETS[@]}"; do
    echo "Building for $target..."
    zig build -Dtarget=$target -Doptimize=ReleaseFast
    
    output_name="z4-${VERSION}-${target}"
    
    cp zig-out/bin/z4 "$OUTPUT_DIR/$output_name"
    echo "  Created: $OUTPUT_DIR/$output_name"
done

echo ""
echo "Build complete! Binaries in $OUTPUT_DIR/"
ls -la $OUTPUT_DIR/
