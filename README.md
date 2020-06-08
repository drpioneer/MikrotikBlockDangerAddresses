# MikrotikBlockDangerAddresses

Script for blocking dangerous addresses that tried to connect to the router



Flipping through the Mikrotik logs, I noticed persistent attempts to connect to my routers, such as these:

```
Mmm/dd/yyyy hh:mm:ss disk system, error, critical login failure for user system from xxx.xxx.xxx.xxx via api
```

It was decided to automate the process of neutralizing all attempts to take over my devices. The result is a script that must be run on a schedule with the desired frequency:

https://github.com/drpioneer/MikrotikBlockDangerAddresses/blob/master/danger.rsc

The result of the script is the creation of a black list of addresses, which includes all IP addresses from which unauthorized access attempts were detected:

- log in to a router with a non-existent router name (log line: '**login failure for user XXXXXXX**'),
- select an IPSec password (log line: '**parsing packet failed, possible cause: wrong password**'),
- connect over IPSec with a mismatched offer (log line: '**failed to get valid proposal**').
- select the L2TP password (log line: '**user XXXXXXX authentication failed**'),

To make the design work, you need to add a rule to Firewall/Filter Rules that will neutralize all attempts to connect to our router from the identified IP addresses:

```
/ip firewall filter add action=drop chain=input comment="Dropping dangerous adresses" src-address-list=BlockDangerAddress
```

How it works:

1. Stage
   - All lines indicating an unsuccessful attempt to log in to the router are searched in the log
   - The login and ip address that the user tried to log in from is extracted from each found string
   - The received login is checked for the absence of Mikrotik active user names in the list (there is no such user)
   - The received ip address is checked for presence in the black list. If it is not there, then it is added to the blacklist.

2. Stage
   - All lines indicating an unsuccessful attempt to find an IPSec password are searched in the log
   - The ip address from which the IPSec password was tried is extracted from each line found
   - The received ip address is checked for presence in the black list. If it is not there, then it is added to the blacklist.

3. Stage
   - All lines indicating an unsuccessful IPSec offer are searched in the log
   - The ip address from which the IPSec offer was tried is extracted from each line found
   - The received ip address is checked for presence in the black list. If it is not there, then it is added to the blacklist.

4. Stage
   - All lines indicating failed L2TP authentication are searched in the log
   - The ip address from which failed L2TP authentication was performed is extracted from each found string
   - The received ip address is checked for presence in the black list. If it is not there, then it is added to the blacklist.

------

# MikrotikBlockDangerAddresses

Скрипт для блокировки опасных адресов, которые пытались подключиться к роутеру



Листая журналы Mikrotik-ов обратил внимание на настойчивые попытки подключиться к моим роутерам, подобные таким:

```
Mmm/dd/yyyy hh:mm:ss disk system, error, critical login failure for user system from xxx.xxx.xxx.xxx via api
```

Было решено автоматизировать процесс нейтрализации всех попыток завладеть моими устройствами. Получился скрипт, который необходимо запускать по расписанию с нужной периодичностью: 

https://github.com/drpioneer/MikrotikBlockDangerAddresses/blob/master/danger.rsc

Результат работы скрипта - создание черного списка адресов, в который складываются все IP, откуда были обнаружены попытки несанкционированного доступа:

- залогиниться на роутер с несуществующим именем роутера (строка в журнале: '**login failure for user XXXXXXX**'),
- подобрать пароль IPSec (строка в журнале: '**parsing packet failed, possible cause: wrong password**'),
- подключиться по IPSec c несовпадающим предложением (строка в журнале: '**failed to get valid proposal'**').
- подобрать пароль L2TP (строка в журнале: '**user XXXXXXX authentication failed**'),

Чтобы конструкция заработала, необходимо добавить в Firewall/Filter Rules правило, которое будет нейтрализовать все попытки соединиться с нашим роутером с выявленных IP-адресов:

```
/ip firewall filter add action=drop chain=input comment="Dropping dangerous adresses" src-address-list=BlockDangerAddress
```

Как это работает:

1. Этап
   - В журнале выискиваются все строки, указывающие на неудачную попытку залогиниться на роутер
   - Из каждой найденной строки вычленяется login и ip-адрес, с которого пытались залогиниться
   - Полученный login проверяется на предмет отсутствия в списке имен активных пользователей Mikrotik-а (такого user-а не существует)
   - Полученный ip-адрес проверяется на наличие в черном списке. Если его там нет, тогда добавляется в черный список.

2. Этап
   - В журнале выискиваются все строки, указывающие на неудачную попытку подобрать пароль IPSec
   - Из каждой найденной строки вычленяется ip-адрес, с которого пытались подобрать пароль IPSec
   - Полученный ip-адрес проверяется на наличие в черном списке. Если его там нет, тогда добавляется в черный список.

3. Этап
   - В журнале выискиваются все строки, указывающие на неудачное предложение IPSec
   - Из каждой найденной строки вычленяется ip-адрес, с которого пытались подобрать предложение IPSec
   - Полученный ip-адрес проверяется на наличие в черном списке. Если его там нет, тогда добавляется в черный список.

4. Этап
   - В журнале выискиваются все строки, указывающие на неудачную аутентификацию по L2TP
   - Из каждой найденной строки вычленяется ip-адрес, с которого производилась неудачная аутентификация по L2TP
   - Полученный ip-адрес проверяется на наличие в черном списке. Если его там нет, тогда добавляется в черный список.

------

