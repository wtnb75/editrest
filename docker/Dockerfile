FROM python:3-alpine
ARG GH_BRANCH=main
RUN --mount=type=cache,target=/root/.cache \
  pip install https://github.com/wtnb75/editrest/archive/refs/heads/${GH_BRANCH}.zip
ENTRYPOINT ["editrest"]
