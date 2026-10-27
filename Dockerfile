FROM python:3.12-slim AS build
WORKDIR /build
COPY pyproject.toml requirements-server.txt ./
COPY vpcomm ./vpcomm
RUN pip wheel --no-cache-dir --wheel-dir /wheels -r requirements-server.txt . \
    && pip wheel --no-cache-dir --wheel-dir /wheels setuptools

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir --no-index --find-links=/wheels vpcomm \
    && rm -rf /wheels \
    && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin vpcomm
USER 10001:10001
EXPOSE 8765
CMD ["vpcomm-server", "--host", "0.0.0.0"]
