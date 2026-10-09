# Build context is the repository root:
#   docker build -f examples/demo_app/Dockerfile .
FROM composer:2 AS build

WORKDIR /app

COPY composer.json composer.lock ./
RUN composer install --no-interaction --no-progress

FROM php:8.3-cli

# The agent's transport speaks HTTPS to the ingestion API.
RUN docker-php-ext-install curl && \
    useradd --create-home --uid 1000 guard

COPY --from=build /app/vendor /app/vendor
COPY src/ /app/src/
COPY examples/demo_app/ /app/examples/demo_app/

LABEL org.opencontainers.image.title="guard-agent-php demo" \
    org.opencontainers.image.description="Containerized Guard Agent demo: a small PHP service streaming security telemetry to a Guard Core ingestion endpoint" \
    org.opencontainers.image.source="https://github.com/Guard-Core/guard-agent-php" \
    org.opencontainers.image.licenses="MIT"

ENV GUARD_AGENT_ENDPOINT=https://api.guard-core.com \
    GUARD_AGENT_PROJECT_ID=demo-project

USER guard
WORKDIR /app

EXPOSE 8080

CMD ["php", "-S", "0.0.0.0:8080", "examples/demo_app/index.php"]
