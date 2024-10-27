FROM python:3.12.4-alpine3.20 AS builder

RUN pip install poetry==1.7.1

ENV POETRY_NO_INTERACTION=1 \
    POETRY_VIRTUALENVS_IN_PROJECT=1 \
    POETRY_VIRTUALENVS_CREATE=1 \
    POETRY_CACHE_DIR=/tmp/poetry_cache

WORKDIR /app

COPY pyproject.toml poetry.lock ./
# poetry complains if README.md is not present (there are build benefits to create empty one instead of copying the real one)
RUN touch README.md

RUN poetry install --without dev --no-root && rm -rf $POETRY_CACHE_DIR

####################################################################################################

FROM python:3.12.4-alpine3.20 AS runtime

RUN apk update --no-cache && apk upgrade --no-cache
RUN apk upgrade busybox libcrypto3 libssl3 libexpat libcurl

# installing iputils to gain access to ping command
RUN apk add --no-cache git iputils

RUN pip install --upgrade pip

ENV VIRTUAL_ENV=/app/.venv \
    PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    # FIXME: not sure why PYTHONPATH is needed for this to work
    PYTHONPATH="/app"

COPY --from=builder ${VIRTUAL_ENV} ${VIRTUAL_ENV}

COPY alembic.ini ./app/alembic.ini
COPY alembic ./app/alembic
COPY urlpinger ./app/urlpinger
# COPY config.json ./app/config.json

WORKDIR /app

# CMD ["python", "urlpinger/main.py"]
