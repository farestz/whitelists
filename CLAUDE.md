# Whitelists

Генерация v2ray/xray-совместимых `whitedomains.dat` и `whiteips.dat` с белыми списками РФ.

## Сборка

```bash
docker build --output=. .
```

Результат: `whitedomains.dat`, `whiteips.dat`, `*.sha256sum` в текущей директории.

## Использование в клиентах

Тег `DIRECT` — указывать в routing rules:
- `ext:whitedomains.dat:direct` — домены
- `ext:whiteips.dat:direct` — IP-адреса

## Источники данных

Upstream (скачиваются при сборке):
- [artembolotov/custom-geosite](https://github.com/artembolotov/custom-geosite) → `lists/direct.txt`
- [hxehex/russia-mobile-internet-whitelist](https://github.com/hxehex/russia-mobile-internet-whitelist) → `whitelist.txt`, `cidrwhitelist.txt`

Кастомные (коммитятся в репо):
- `lists/domains-custom.txt` — домены, по одному на строку
- `lists/ips-custom.txt` — CIDR-диапазоны, по одному на строку

### Формат кастомных доменов

```
example.ru          # domain: match (домен + поддомены), по умолчанию
full:exact.host.ru  # full: только точное совпадение
domain:example.ru   # domain: явно
regex:^.*\.ru$      # regex: регулярное выражение
```

## Технические детали

- Go 1.26, zero dependencies
- Protobuf-кодирование hand-rolled (формат v2ray-core GeoSite/GeoIP)
- Дедупликация доменов и CIDR при мерже источников
