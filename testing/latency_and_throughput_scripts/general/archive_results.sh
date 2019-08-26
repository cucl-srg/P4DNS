#!/bin/zsh

if [[ $# -ne 2 ]] || [[ ! -d $1 ]]; then
	echo "Usage: $0 <source folder> <target file>"
fi


echo "Starting compression."
tar -c $1 | pbzip2 -c > $2
echo "Compression finished!"
