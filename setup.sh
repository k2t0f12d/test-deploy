#!/usr/bin/env bash

# NOTE: uncomment this to get debugging output from BASH
#set -x

compare_versions() {

        # Only accept numerical inputs
        [[ $1 =~ ^[0-9][0-9.]*$ ]] || return 255
        [[ $2 =~ ^[0-9][0-9.]*$ ]] || return 255

        local IFS=.
        local i ver1=($1) ver2=($2)

        # Compare version string lengths; if ver2 has
        # more version places, fill the missing places
        # in ver1 with zeros.
        for((i=${#ver1[@]}; i<${#ver2[@]}; i++)); do
                ver1[i]=0
        done

        for((i=0; i<${#ver1[@]}; i++)); do

                # If ver1 has more version places than ver2
                # fill the extra places in ver2 with zero.
                if [[ -z ${ver2[i]} ]]; then
                        ver2[i]=0
                fi

                # Case greater than returns 1
                if((10#${ver1[i]} > 10#${ver2[i]})); then
                        return 1
                fi

                # Case less than returns 2
                if((10#${ver1[i]} < 10#${ver2[i]})); then
                        return 2
                fi
        done

        return 0
}

if test -z "${PYTHON_MIN_VERSION}"; then
        PYTHON_MIN_VERSION='3.6'
fi

compare_versions "$(python -V | cut -d' ' -f2)" "${PYTHON_MIN_VERSION}"

# Do not accept python versions less than v3.6.x
if test $? -gt 1; then
        echo "Your python is too old, upgrade to Python 3.6 latest."
        exit
fi

compare_versions `pip --disable-pip-version-check show pip | grep Version: | cut -d' ' -f2` `pip --disable-pip-version-check search pip | grep '^pip\ ' | tr -s " " " " | cut -d' ' -f2 | sed -e 's/[()]//g'`

# Upgrade pip if there is a newer version
if test $? -gt 1; then
        pip install --upgrade pip
fi

# Load python invoke, if missing
python -c 'import invoke' 2>&1 >/dev/null
test $? -eq 0 || pip install invoke

pip install -r requirements.txt
