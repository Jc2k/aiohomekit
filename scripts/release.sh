#! /bin/sh

poetry version patch
git commit -a -m "Version bump"
git tag -a -s `poetry version | awk '{ print $2; }'`
git push --tags
git push

