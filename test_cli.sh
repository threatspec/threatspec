#!/usr/bin/env bash
set -e

basedir=$(pwd)

if [ -z "$1" ]; then
    KEEP='FALSE'
    tempdir=$(mktemp -d)
else
    KEEP='TRUE'
    tempdir="$1"
fi

echo 'Activating environment'
source .venv/bin/activate

echo 'Cleaning up dist'
test -d 'dist' && rm dist/*

echo 'Creating package'
python setup.py sdist >/dev/null

distfile=$(ls -1 dist/*.tar.gz | head -1)
echo "Found dist file $distfile"

echo 'Deactivating virtual environment'
deactivate > /dev/null

echo "Changing to temp directory $tempdir"
pushd $tempdir

echo 'Creating new environment'
virtualenv -ppython3.6 .venv > /dev/null

echo 'Activating new environment'
source .venv/bin/activate > /dev/null

echo "Installing dist file $basedir/$distfile"
pip install $basedir/$distfile > /dev/null

echo 'Testing threatspec version'
threatspec --version

echo 'Downloading source file' # TODO - replace with a github url
cp /home/zeroxten/Downloads/src/threatspec/threatspec_examples/simple_web.go .

echo 'Initialising threatspec'
threatspec init

echo 'Running threatspec'
threatspec -l debug run

echo 'Validating output'
cat threatmodel/*.json

if [ "$KEEP" = "FALSE" ]; then
    echo '***************'
    echo 'Deactivating environment'
    deactivate

    echo 'Returning to basedir'
    popd

    echo 'Cleaning up tempdir'
    rm -rf $tempdir
fi
