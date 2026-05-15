.PHONY: dev dev-down rebuild logs test

dev: rebuild
	docker compose up -d

rebuild:
	docker compose build --no-cache

dev-down:
	docker compose down

logs:
	docker compose logs -f

test: dev
	cd waffleiron-web && npx playwright test
