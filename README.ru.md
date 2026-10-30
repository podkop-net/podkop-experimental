# podkop-exp

[English](README.md)

Репозиторий для тестов новой функциональности [podkop](https://github.com/itdoginfo/podkop). То, что проверяется здесь, может потом войти в podkop, измениться или исчезнуть.

podkop-exp работает с настройками podkop (`/etc/config/podkop`) и его страницей в LuCI и ставится вместо пакета podkop: вместе они не работают. Бэкенд написан на Go и содержит sing-box внутри, отдельный пакет sing-box не нужен.

## Установка

OpenWrt 24.10 или новее, не меньше 80 МБ оперативной памяти. В консоли роутера:

```sh
sh <(wget -O - https://raw.githubusercontent.com/podkop-net/podkop-experimental/main/install.sh)
```

Установщик проверяет роутер, предлагает удалить podkop и пакеты, которые конфликтуют с podkop-exp (а если не хватает места — ненужные podkop-exp пакеты sing-box), и ставит podkop-exp и его страницу, и, по желанию, русский перевод. Настройки podkop переводятся в формат podkop-exp, прежний файл остаётся как `/etc/config/podkop.pre-0.8.8`.

Вернуться на podkop: удалите `podkop-exp`, `luci-app-podkop-exp` и `luci-i18n-podkop-exp-ru`, верните прежние настройки командой `mv /etc/config/podkop.pre-0.8.8 /etc/config/podkop` (если такого файла нет, удалите `/etc/config/podkop`), затем поставьте podkop по его README.

Проблемы и вопросы — в [issues](https://github.com/podkop-net/podkop-experimental/issues).
