#!/bin/bash
base_dir="rule"

for dir in "$base_dir"/*/; do
    folder_name=$(basename "$dir")
    json_file="$dir/$folder_name.json"
    if [[ -f "$json_file" ]]; then
        output_file="$dir/$folder_name.srs"
        
        sing-box rule-set compile --output "$output_file" "$json_file"
        
        echo "Processed: $json_file -> $output_file"
    else
        echo "JSON file not found: $json_file"
    fi
done