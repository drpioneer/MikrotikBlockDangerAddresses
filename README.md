# Script for blocking dangerous IPv4 addresses from which they tried to connect to the router

The script automatically blocks IPv4 addresses of intruders probing Mikrotik routers from external networks. The script has no dependencies on third-party functions and scripts. The setting involves editing the values of local variables at the beginning of the script body, a brief description of which is present in the comments. The body of the script must be uploaded to 'System/Scripts', run manually from the terminal window with the command '/system script run <script name>', read the information provided and, if necessary, adjust the operating settings. Next, the startup is configured according to the schedule from the 'System/Scheduler' with the required time period (the typical value is units of minutes).

The script works by creating a blacklist of IPv4 addresses to block them.
The blacklist is formed in two different independent ways:
  1. based on the analysis of the device's log entries
  2. using pre-configured Firewall rules

The 1st method is triggered every time the script is run. On the first launch, the entire device log is checked, and on subsequent launches, only the unchecked part of the log is checked. This is done to increase the speed of subsequent log checks. 

The 2nd method is initially disabled, this is done because the Firewall may already be configured and interference with its operation is not desirable.
The 2nd method is activated manually by setting the 'fwUsag' variable to 'true'.
After activating the 2nd method, the script configures the Firewall according to the principle: "everything that is not allowed is prohibited" and from that moment on, even if the script is not running, all attempts from outside to probe the router will be considered unauthorized.
Along the way, when using the 2nd method, each time the script is run, it checks for pre-configured Firewall rules and, if they are missing, installs the missing ones. The script searches for missing Firewall rules based on the comments in the lists: 'Firewall/Filter Rules', 'Firewall/Raw', 'Firewall/Layer7 Protocols'. After installing the Firewall rules, the user needs to manually arrange them according to their preferences. To avoid unexpected blocking when installing new rules, the blocking rules are DISABLED (!!!). The user does the movement and activation of the blocking rules manually. FIREWALL rules are configured in the active 'Safe Mode' mode in case of unexpected loss of connection with the router and for automatic reset of settings to their original state. After completing the settings, the 'Safe Mode' mode must be deactivated. If the blocking rules are left disabled, the script will notify you about this.

As a result, all accesses to the router that have not passed the Firewall check or are displayed in the device log as unauthorized access attempts are blacklisted and blocked for the time specified in the 'timeout' variable. The typical number of entries in the blacklist when blocked for 8 hours can range from several hundred to several thousand (!!!) entries, and directly depends on the activity of intruders.

The script was tested on current versions of RouterOS 6.49.++ and 7.16.++.

Known issues:
* the script may fail if Firewall rules control is enabled and there are identical rules with different comments in the list.
* to prevent the script from blocking addresses that affect the performance of network equipment (DNS provider, upstream address, etc.), it makes sense to whitelist them in advance.

-------------------
# Cкрипт блокировки опасных IPv4 адресов, с которых пытались произвести подключение к роутеру

Скрипт автоматически блокирует IPv4 адреса злоумышленников, прощупывающих маршрутизаторы Mikrotik из внешних сетей. Скрипт не имеет зависимостей от сторонних функций и скриптов. Настройка подразумевает правку значений локальных переменных в начале тела скрипта, краткое описание которых присутствует в комментариях. Тело скрипта необходимо закинуть в 'System/Scripts', запустить вручную из окна терминала командой '/system script run <имя скрипта>', ознакомиться с представленной информацией и при необходимости подправить рабочие настройки. Далее производится настройка запуска по расписанию из 'System/Scheduler' с необходимым периодом времени (типовое значение составляет единицы минут).

Работа скрипта сводится к формированию чёрного списка IPv4 адресов для их блокировки.
Формирование чёрного списка происходит двумя разными независимыми способами:
  1. на основе анализа записей журнала устройства
  2. при помощи преднастроенных правил Firewall

1й способ срабатывает каждый раз при запуске скрипта. При первом запуске проверяется весь журнал устройства, а при последующих запусках проверяется только непроверенная часть журнала. Так сделано для увеличения скорости последующих проверок журнала. 

2й способ изначально отключен, это сделано из соображения, что Firewall может быть уже настроен и вмешательство в его работу не желательно.
Активация 2го способа производится вручную, путём присвоения переменной 'fwUsag' значения 'true'.
После активации 2го способа скрипт настраивает Firewall по принципу: "запрещено всё, что не разрешено" и с этого момента, даже если скрипт не запущен, все попытки из вне прощупать роутер будут считаться несанкционированными.
Попутно, при задействовании 2го способа, при каждом запуске скрипт проверяет наличие преднастроенных правил Firewall и в случае их отсутствия производит установку недостающих. Поиск недостающих правил Firewall скрипт производит по комментариям в списках: 'Firewall/Filter Rules', 'Firewall/Raw', 'Firewall/Layer7 Protocols'. После установки правил Firewall пользователю необходимо расположить их вручную согласно своим предпочтениям. Для исключения неожиданной блокировки при установке новых правил, правила блокировки устанавливаются ОТКЛЮЧЕННЫМИ (!!!). Перемещение и активацию правил блокировки пользователь делает самостоятельно, вручную. Настройка правил FIREWALL производится в активном режиме 'Safe Mode' на случай неожиданной потери связи с роутером и для автоматического отката настроек в исходное состояние. По окончании настроек режим 'Safe Mode' необходимо деактивировать. Если правила блокировки оставить отключенными - скрипт будет об этом оповещать.

В итоге, все обращения к роутеру, не прошедшие проверку Firewall или отображённые в журнале устройства, как попытки несанкционированного доступа, попадают в черный список и блокируются на время, заданное в переменной 'timeout'. Типовое количество записей в чёрном списке при блокировке на 8 часов может составлять от нескольких сотен до нескольких тысяч (!!!) записей, и напрямую зависит от активности злоумышленников.

Обкатка скрипта проводилась на актуальных версиях RouterOS 6.49.++ и 7.16.++ .

Известные проблемы:
* работа скрипта может завершаться ошибкой, при включенном контроле правил Firewall и наличии в списке одинаковых правил с отличающимися комментариями.
* для предотвращения блокировки скриптом адресов, влияющих на работоспособность сетевого оборудования (DNS провайдера, адрес вышестоящего узла и т.п.), имеет смысл заранее внести их в белый список.
------------------------
Discussion of the script * Обсуждение скрипта: https://forummikrotik.ru/viewtopic.php?t=11586

**If you use a script, mark it with an asterisk, it's not difficult for you, but it's nice for me**

**Используете скрипт - отметьте это звездочкой, Вам не сложно, а мне приятно!**




