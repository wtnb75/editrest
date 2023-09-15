FROM python:3-alpine
ARG GH_BRANCH=main
RUN apk add --no-cache vim
ENV EDITOR=vim
RUN --mount=type=cache,target=/root/.cache \
  pip install https://github.com/wtnb75/editrest/archive/refs/heads/${GH_BRANCH}.zip
LABEL org.opencontainers.image.source="https://github.com/wtnb75/editrest"
ENTRYPOINT ["editrest"]
