# Трансляция между метками безопасности CIPSO и ГОСТ Р 58256-2018 (Astra)

Данный модуль предоставляет iptables таргет TRIPSO, который перекодирует пакеты
содержащие метки безопасности между протоколами CIPSO и ГОСТ Р 58256-2018
(RFC 1108 в модификации Astra Linux SE).

Пример использования:

    # iptables -t security -I INPUT -j TRIPSO --to-cipso
    # iptables -t security ! -o lo -I OUTPUT -j TRIPSO --to-astra

Данная конфигурация меняет метку на входящих пакетах из формата ГОСТ в CIPSO и
для исходящих пакетов (за исключением локального интерфейса) с CIPSO на ГОСТ.

* **Домашняя страница**: <https://github.com/vt-alt/tripso>

* **Сообщить об ошибке**: <https://bugzilla.altlinux.org>

* **Автор**: vt @ basealt.ru, (c) 2018-2021.

* **Лицензия**: GPL-2.0-only.

