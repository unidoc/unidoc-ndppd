  git add -A
  git commit -m "ci: build inside docker run instead of job-level container (JS actions don't run in Alpine arm64 containers)"
  git push origin master
  git tag -d v1.0.0
  git push origin :refs/tags/v1.0.0
  git tag v1.0.0
  git push origin v1.0.0


