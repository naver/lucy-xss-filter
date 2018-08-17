#!/bin/bash
asciidoctor docs/index.adoc -o target/index.html
asciidoctor docs/kr/index.adoc -o target/kr/index.html
cp -R docs/kr/image target/kr/image

