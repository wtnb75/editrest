FROM python:3-alpine AS dev
ARG GH_BRANCH=main
RUN apk add --no-cache git
RUN git clone --depth=1 -b ${GH_BRANCH} https://github.com/wtnb75/editrest
RUN echo "VERSION = \"0.0.0.dev0+$(printf '%s' "${GH_BRANCH}" | tr -cs 'a-zA-Z0-9' '.')\"" > editrest/editrest/version.py
RUN cd editrest && pip install build && python -m build -w
RUN cp editrest/dist/*.whl /editrest.whl

FROM python:3-alpine
RUN apk add --no-cache vim
ENV EDITOR=vim
COPY --from=dev /editrest/dist /dist
RUN --mount=type=cache,target=/root/.cache \
    pip install /dist/*.whl
LABEL org.opencontainers.image.source="https://github.com/wtnb75/editrest"
ENTRYPOINT ["editrest"]
