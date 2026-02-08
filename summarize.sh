#!/bin/bash

OUTPUT_FILE="./summary.txt"
> "$OUTPUT_FILE"

echo "Collecting files into $OUTPUT_FILE..."

{
    find ./src ./panel ./extensions ./modules ./traffic_profiles -type f 2>/dev/null
    find . -maxdepth 1 -type f \( -name "*.sh" -o -name "*.rs" -o -name "*.md" -o -name "*.toml" \)
} | while read -r filepath; do
    
    # Use XML tags which are LLM-friendly and don't break UI
    echo "// $filepath " >> "$OUTPUT_FILE"
    
    # Dump content
    cat "$filepath" >> "$OUTPUT_FILE"
    

done

echo "Done."
