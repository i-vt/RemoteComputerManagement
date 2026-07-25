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

# --- 1. Project tree at the top of the summary ---
{
    echo "===== PROJECT TREE ====="
    echo
    if command -v tree >/dev/null 2>&1; then
        tree "$TARGET_DIR"
    else
        # Fallback when `tree` is not installed
        echo "$TARGET_DIR"
        find "$TARGET_DIR" -print | sort | sed -e "s|[^/]*|  |g"
    fi
    echo
    echo "===== FILE CONTENTS ====="
    echo
} >> "$OUTPUT_FILE"

# --- 2. File contents (each file listed exactly once) ---
{
    # All files under these dirs, any extension (except .mp3)
    find "$TARGET_DIR/src" "$TARGET_DIR/panel" "$TARGET_DIR/extensions" "$TARGET_DIR/modules" "$TARGET_DIR/traffic_profiles" \
        -type f ! -name "*.mp3" 2>/dev/null

    # Matching extensions everywhere ELSE — the 5 dirs above are pruned
    # so their files can't be picked up a second time
    find "$TARGET_DIR" \
        \( -path "$TARGET_DIR/src" -o -path "$TARGET_DIR/panel" \
           -o -path "$TARGET_DIR/extensions" -o -path "$TARGET_DIR/modules" \
           -o -path "$TARGET_DIR/traffic_profiles" \) -prune -o \
        -type f \
        \( -name "*.sh" -o -name "*.json" -o -name "*.rs" -o -name "*.md" -o -name "*.toml" -o -name "*.html" -o -name "*.js" -o -name "*.css" -o -name "*.py" \) \
        ! -name "*.mp3" ! -name "*.txt" -print
} | while read -r filepath; do

    echo "// $filepath" >> "$OUTPUT_FILE"
    cat "$filepath" >> "$OUTPUT_FILE"

done

echo "Done."
