#!/bin/sh
set -eu

source_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
output_dir=${1:-"$source_dir/dist"}
version=$(sed -n 's/^Version: //p' "$source_dir/DEBIAN/control")
stage=$(mktemp -d)
chmod 755 "$stage"
trap 'rm -rf -- "$stage"' EXIT

cp -a "$source_dir/DEBIAN" "$source_dir/usr" "$stage/"
cp "$source_dir/README.md" "$stage/usr/share/doc/h3c-campus/README.md"
cp "$source_dir/LICENSE" "$stage/usr/share/doc/h3c-campus/copyright"
mkdir -p "$output_dir"
dpkg-deb --build --root-owner-group "$stage" "$output_dir/h3c-campus_${version}_all.deb"
