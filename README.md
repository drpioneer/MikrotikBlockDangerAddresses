# MikrotikBlockDangerAddresses - скрипт блокировки опасных IP-адресов, с которых пытались произвести подключение к роутеру.

Скрипт предназначен для автоматической блокировки злоумышленников из внешних сетей, сканирующих маршрутизаторы. 

Код скрипта содержит в себе всё необходимое для работы и не имеет зависимостей от сторонних функций и скриптов. 
Для работы, скрипт необходимо добавить в System/Scripts и настроить запуск в System/Sheduler с необходимым периодом, например 1 мин.
Работосопособность скрипта проверялась только на актуальных версиях RouterOS 6.49+.
Настройка скрипта производится путём правки значений локальных переменных в начале тела скрипта.
Краткое описание переменных содержится в комментариях.

Работа скрипта сводится к формированию чёрного списка адресов и их блокировке.
Формирование чёрного списка адресов производится путём анализа записей журнала и специально настроенных правил Firewall.
Первые запуски скрипта настоятельно рекомендуется производить вручную из окна терминала, это нужно для чтения отчёта о состоянии и при необходимости внесения правок в настройки. 
Запуск настроенного скрипта должен производиться по расписанию.

В текущей версии  скрипта уделено внимание контролю Firewall для облегчения настройки роутера "с нуля".
По умолчанию контроль Firewall отключен, это сделано из соображения, что Firewall может быть уже настроен и вмешательство в его работу не желательно.
Для включения контроля Firewall необходимо присвоить значение 'true' переменной 'firewallUsage', после чего скрипт будет производить проверку установки набора правил Firewall при каждом запуске. При отсутствии любого из правил происходит его автоматическое добавление. Поиск правил производится по комментариям. Работа ведётся со списками: 'Firewall/Filter Rules', 'Firewall/Raw', 'Firewall/Layer7 Protocols'. После установки правил Firewall пользователю необходимо их расположить вручную согласно своим предпочтениям. Для исключения неожиданной блокировки при установке новых правил, правила блокировки устанавливаются ОТКЛЮЧЕННЫМИ (!!!). Перемещение и включение правил блокировки пользователь производит ВРУЧНУЮ, рекомендуется это делать в режиме 'Safe Mode', для того чтобы в случае потери связи с роутером, когда режим 'Safe Mode' отключился, все настройки вернулись как были. Важно не забыть отключить 'Safe Mode' после настройки. Если правила блокировки оставить отключенными - скрипт будет оповещать об этом.

Известные проблемы: работа скрипта может завершаться ошибкой, при включенном контроле правил Firewall и наличии в списке одинаковых правил с отличающимися комментариями.

https://forummikrotik.ru/viewtopic.php?p=91125#p91125
