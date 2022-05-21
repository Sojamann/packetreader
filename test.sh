#!/bin/bash

set -e

THIS_DIR="$(dirname $0)"

usage() {
    printf "USAGE: $(basename $0) path/to/file\n"
}

[ -z "$1" ] && (usage ; exit 1)

path=$(readlink -f "$1")

[ -f "$path" ] || (echo "The provided file does not exist" ; exit 1)


pprintf=$(mktemp)
tsharkf=$(mktemp)
trap "rm $pprintf $tsharkf" EXIT

(go run $THIS_DIR/examples/pprint.go "$path" | cut -d " " -f 1,2,4) > $pprintf
tshark -r "$path" -t ud -T fields -e _ws.col.Time -e frame.len > $tsharkf


while IFS="|" read -r t_ts t_size p_ts p_size; do

    if [ "$t_size" != "$p_size" ]; then
        echo "Size-Missmatch: $tsize(tshark) $psize(pcapreader)"
    fi

    if [ "$t_ts" != "$p_ts" ]; then
        echo "Ts-Missmatch: $t_ts(tshark) $p_ts(pcapreader)"
    fi

done < <(paste "$tsharkf" "$pprintf" | tr '\t' '|')
