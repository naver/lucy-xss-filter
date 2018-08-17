#!/bin/bash
./build_guides.sh
git checkout gh-pages
cp target/index.html .
cp -R target/kr .
git add --all
git commit -m 'Publish to github pages'
git push

