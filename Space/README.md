# Pulse Relay 2.2

Сайт с панелью + WebSocket для приложения Pulse Control 5.4.

* Панель: `/`
* Проверка живости: `/healthz` → `{"ok":true}` и `/api/health`
* Порт берётся из `PORT` (Render/Railway подставляют сами), иначе 8443.

## Деплой на Render
1. GitHub → New repository → upload files → перетащить всё из этой папки.
2. Render → New → Web Service → выбрать репозиторий.
3. Plan: **Free**. Build: `npm install --omit=dev`. Start: `node server.js`.
4. Готово: `https://<имя>.onrender.com`

Настроек и переменных окружения не требуется.
