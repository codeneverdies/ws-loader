#!/bin/sh

filename="funcs"

while read -r line; do
    echo $(./dj "$line")
done < "$filename"
