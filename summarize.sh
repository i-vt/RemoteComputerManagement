#!/bin/bash

TARGET_DIR="${1:-.}"
TARGET_DIR="${TARGET_DIR%/}"

if [[ ! -d "$TARGET_DIR" ]]; then
    echo "Error: '$TARGET_DIR' is not a directory" >&2
    exit 1
fi

if [[ "$TARGET_DIR" == "." ]]; then
    OUTPUT_FILE="./summary.txt"
else
    name_prefix="${TARGET_DIR//\//_}"
    name_prefix="${name_prefix#./}"
    OUTPUT_FILE="./${name_prefix}_summary.txt"
fi

> "$OUTPUT_FILE"

echo "Collecting files from $TARGET_DIR into $OUTPUT_FILE..."

{
    find "$TARGET_DIR/src" "$TARGET_DIR/panel" "$TARGET_DIR/extensions" "$TARGET_DIR/modules" "$TARGET_DIR/traffic_profiles" \
        -type f ! -name "*.mp3" 2>/dev/null

    find "$TARGET_DIR" -type f \
        \( -name "*.sh" -o -name "*.json" -o -name "*.rs" -o -name "*.md" -o -name "*.toml" -o -name "*.html" -o -name "*.js" -o -name "*.css" -o -name "*.py" \) \
        ! -name "*.mp3" ! -name "*.txt"
} | while read -r filepath; do

    echo "// $filepath" >> "$OUTPUT_FILE"
    cat "$filepath" >> "$OUTPUT_FILE"

done

echo "Done."