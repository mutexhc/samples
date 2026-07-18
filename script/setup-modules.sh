#!/usr/bin/env bash

set -euxo pipefail

mkdir -p .modules

clone() {
    local repository="$1"
    local destination="$2"

    if [ -d "$destination/.git" ]; then
        echo "Já existe: $destination"
        return
    fi

    mkdir -p "$(dirname "$destination")"
    git clone --depth 1 "$repository" "$destination"
}

clone \
  https://github.com/vxunderground/MalwareSourceCode.git \
  .modules/vxunderground/MalwareSourceCode

clone \
  https://github.com/objective-see/Malware.git \
  .modules/objective-see/Malware

clone \
  https://github.com/RamadhanAmizudin/malware.git \
  .modules/RamadhanAmizudin/malware

clone \
  https://github.com/RPISEC/Malware.git \
  .modules/RPISEC/Malware

clone \
  https://github.com/gbrindisi/malware.git \
  .modules/gbrindisi/malware

clone \
  https://github.com/Endermanch/MalwareDatabase.git \
  .modules/Endermanch/MalwareDatabase

clone \
  https://github.com/rshipp/awesome-malware-analysis.git \
  .modules/rshipp/awesome-malware-analysis