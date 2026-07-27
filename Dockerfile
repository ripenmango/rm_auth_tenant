# syntax=docker/dockerfile:1

FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        libpq-dev \
        curl \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml ./

# NOTE: pyproject.toml's drf_base/rm_auth dependencies are file:// wheel
# paths under /Users/lsharma/personal/... (host paths) -- these won't
# resolve inside this container unless those dist/ folders are also copied
# or bind-mounted in. Rebuild drf-base's and rm_auth's wheels and either (a)
# copy their dist/*.whl into this build context first, or (b) mount them as
# build context/volumes, before `docker compose build` will actually
# succeed. This mirrors the same pre-existing assumption in rm_auth_project's
# own Dockerfile -- not something specific to this repo.
RUN pip install --upgrade pip setuptools wheel \
    && pip install ".[dev]"

COPY . .

EXPOSE 8001

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8001/admin/login/ || exit 1

CMD ["python", "manage.py", "runserver", "0.0.0.0:8001"]
