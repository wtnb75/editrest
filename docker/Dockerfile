FROM python:3-alpine AS dev
ARG GH_BRANCH=main
RUN apk add --no-cache git
RUN git clone --depth=1 -b ${GH_BRANCH} https://github.com/wtnb75/editrest
RUN echo "VERSION = \"${GH_BRANCH}\"" > editrest/editrest/version.py
RUN cd editrest && python setup.py bdist_wheel
RUN cp editrest/dist/*.whl /editrest.whl

FROM python:3-alpine
RUN apk add --no-cache vim
ENV EDITOR=vim
COPY --from=dev /editrest/dist /dist
RUN --mount=type=cache,target=/root/.cache \
    pip install /dist/*.whl
LABEL org.opencontainers.image.source="https://github.com/wtnb75/editrest"
ENTRYPOINT ["editrest"]
