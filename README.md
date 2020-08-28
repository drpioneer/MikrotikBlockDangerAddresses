# MikrotikBlockDangerAddresses

Script for blocking dangerous IP addresses that were used to connect to the router.



Flipping through the Mikrotik logs, my attention was drawn to persistent attempts to connect to my routers, such as these:

```
Mmm/dd/yyyy hh:mm:ss disk system, error, critical login failure for user system from xxx.xxx.xxx.xxx via api
```

It was decided to automate the process of neutralizing all attempts to take possession of my devices. The result is a script that must be run on a schedule with the desired frequency:

https://github.com/drpioneer/MikrotikBlockDangerAddresses/blob/master/danger.rsc

The result of the script is the creation of a black list of addresses, which includes all IP addresses from which unauthorized access to the router was detected, such as:

- log in to a router with a non-existent router name (log line: '**login failure for user XXXXXXX**'),
- select an IPSec password (log line: '**parsing packet failed, possible cause: wrong password**'),
- connect over IPSec with a mismatched offer (log line: '**failed to get valid proposal**').
- select the L2TP password (log line: '**user XXXXXXX authentication failed**'),
- log in to the router from an unsigned network (log line: '**denied winbox/dude connect from**')

To make the design work, you need to add a rule to Firewall/Filter Rules that will neutralize all attempts to connect to the router from the identified IP addresses:

```
/ip firewall filter add action=drop chain=input comment="Dropping dangerous adresses" src-address-list=BlockDangerAddress
```

***How it works:***

In the list of Firewall rules, the user adds a new one designed to block all attempts to connect to the router from IP addresses that are in the black list. The black list of addresses is generated automatically by the script during periodic analysis of the device log. The log is analyzed in several steps:

1. step
   - All lines indicating an unsuccessful attempt to log in to the router are searched in the log
   - The login and ip address that the user tried to log in from is extracted from each found string
   - The received login is checked for the absence of Mikrotik active user names in the list (there is no such user)
   - The received ip address is checked for presence in the black list. If it is not there, then it is added to the blacklist.

2. step
   - All lines indicating an unsuccessful attempt to find an IPSec password are searched in the log
   - The ip address from which the IPSec password was tried is extracted from each line found
   - The received ip address is checked for presence in the black list. If it is not there, then it is added to the blacklist.

3. step
   - All lines indicating an unsuccessful IPSec offer are searched in the log
   - The ip address from which the IPSec offer was tried is extracted from each line found
   - The received ip address is checked for presence in the black list. If it is not there, then it is added to the blacklist.

4. step
   - All lines indicating failed L2TP authentication are searched in the log
   - The ip address from which failed L2TP authentication was performed is extracted from each found string
   - The received ip address is checked for presence in the black list. If it is not there, then it is added to the blacklist.

5. step
  - The log searches for all lines indicating an attempt to connect from an unsigned network
  - The ip address from which the connection attempt was made is extracted from each found string
  - The received ip address is checked for presence in the black list. If it is not there, then it is added to the blacklist.

------

# MikrotikBlockDangerAddresses

Скрипт блокировки опасных IP-адресов, с которых пытались произвести подключение к роутеру.



Листая журналы Mikrotik-ов, мое внимание привлекли настойчивые попытки подключиться к моим роутерам, подобные таким:

```
Mmm/dd/yyyy hh:mm:ss disk system, error, critical login failure for user system from xxx.xxx.xxx.xxx via api
```

Было решено автоматизировать процесс нейтрализации всех попыток завладеть моими устройствами. Получился скрипт, который необходимо запускать по расписанию с нужной периодичностью:

https://github.com/drpioneer/MikrotikBlockDangerAddresses/blob/master/danger.rsc

Результатом работы скрипта является создание черного списка адресов, в который складываются все IP-адреса, с которых были обнаружены попытки несанкционированного доступа к роутеру, такие как:

- залогиниться на роутер с несуществующим именем роутера (строка в журнале: '**login failure for user XXXXXXX**'),
- подобрать пароль IPSec (строка в журнале: '**parsing packet failed, possible cause: wrong password**'),
- подключиться по IPSec c несовпадающим предложением (строка в журнале: '**failed to get valid proposal'**'),
- подобрать пароль L2TP (строка в журнале: '**user XXXXXXX authentication failed**'),
- залогиниться на роутер из непрописанной сети (строка в журнале: '**denied winbox/dude connect from**')

Чтобы конструкция заработала, необходимо добавить в Firewall/Filter Rules правило, которое будет нейтрализовать все попытки подключения к роутеру с выявленных IP-адресов:

```
/ip firewall filter add action=drop chain=input comment="Dropping dangerous adresses" src-address-list=BlockDangerAddress
```

***Как это работает:***

В список правил Firewall, пользователь добавляет новое, предназначеное для блокировки всех попыток подключения к роутеру с IP-адресов, находящихся в чёрном списке. Чёрный список адресов формируется скриптом автоматически в ходе периодического анализа журнала устройства. Анализ журнала производится в несколько шагов:

1. шаг
   - В журнале выискиваются все строки, указывающие на неудачную попытку залогиниться на роутер
   - Из каждой найденной строки вычленяется login и ip-адрес, с которого пытались залогиниться
   - Полученный login проверяется на предмет отсутствия в списке имен активных пользователей Mikrotik-а (такого user-а не существует)
   - Полученный ip-адрес проверяется на наличие в черном списке. Если его там нет, тогда добавляется в черный список.

2. шаг
   - В журнале выискиваются все строки, указывающие на неудачную попытку подобрать пароль IPSec
   - Из каждой найденной строки вычленяется ip-адрес, с которого пытались подобрать пароль IPSec
   - Полученный ip-адрес проверяется на наличие в черном списке. Если его там нет, тогда добавляется в черный список.

3. шаг
   - В журнале выискиваются все строки, указывающие на неудачное предложение IPSec
   - Из каждой найденной строки вычленяется ip-адрес, с которого пытались подобрать предложение IPSec
   - Полученный ip-адрес проверяется на наличие в черном списке. Если его там нет, тогда добавляется в черный список.

4. шаг
   - В журнале выискиваются все строки, указывающие на неудачную аутентификацию по L2TP
   - Из каждой найденной строки вычленяется ip-адрес, с которого производилась неудачная аутентификация по L2TP
   - Полученный ip-адрес проверяется на наличие в черном списке. Если его там нет, тогда добавляется в черный список.

5. шаг
   - В журнале выискиваются все строки, указывающие на попытку подключения из непрописанной сети
   - Из каждой найденной строки вычленяется ip-адрес, с которого производилась попытка подключения
   - Полученный ip-адрес проверяется на наличие в черном списке. Если его там нет, тогда добавляется в черный список.

------

