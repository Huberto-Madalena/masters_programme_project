#!/bin/bash
input_dir="pcaps"
output_dir="pcaps_anon"

mkdir -p "$output_dir"

for file in "$input_dir"/*.pcap; do
    base=$(basename "$file")
    echo "Anonymising $base ..."
    tcprewrite --infile="$file" \
               --outfile="$output_dir/$base" \
               --srcipmap=192.168.0.0/16:10.0.0.0/16 \
               --dstipmap=192.168.0.0/16:10.0.0.0/16 \
	       --enet-smac=00:00:00:00:00:00 \
	       --enet-dmac=00:00:00:00:00:00
done

echo "pcaps anonymised in $output_dir"
