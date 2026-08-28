  git add -A
  git commit -m "ci: install file (needed for the static-binary verify step)"
  git push origin master
  git tag -d v1.0.0
  git push origin :refs/tags/v1.0.0
  git tag v1.0.0
  git push origin v1.0.0


