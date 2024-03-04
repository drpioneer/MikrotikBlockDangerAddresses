# Script for searching and blocking dangerous IP-addresses
# Script uses ideas by podarok66, evgeniy.demin, Virtue, tgrba, denismikh, MMAXSIM, andrey-d, GregoryGost, Chupaka, Jotne, drPioneer.
# https://github.com/drpioneer/MikrotikBlockDangerAddresses/blob/master/danger.rsc
# https://forummikrotik.ru/viewtopic.php?p=70410#p70410
# tested on ROS 6.49.10 & 7.12
# updated 2023/03/04

:global scriptBlckr; # flag of the running script; false=>in progress, true=>idle
:do {
  :local timeoutBL     "8h";  # timeout of blacklist
  :local inIfaceList   "";    # name of input interface list: "internet","WAN",etc=>manual input value; ""=automatic value selection
  :local firewallUsage false; # checking & installing firewall rules
  :local extremeScan   false; # setting log scan level: false=>usual option; true=>extremal option
  :local logEntry      false; # maintaining log entries
  :local staticAddrLst false; # converting blacklist from dynamic to static
  :local nameBlackList "BlockDangerAddress"; # name of blacklist
  :local nameWhiteList "WhiteList";          # name of whitelist
  :local commentRuleBL "dropping dangerous addresses"; # comment for blacklist rule
  :local commentRuleWL "white List of IP-addresses";   # comment for whitelist rule

  # string parsing function
  :local StrParser do={
    :if ([:len [:find $1 $2 -1]]=0) do={:return ""}
    :local startPos ([:find $1 $2 -1]+[:len $2] +1); :local stopPos 0;
    :set $stopPos [:find $1 "\"" $startPos];
    :if ($stopPos<$startPos) do={:set stopPos ($startPos+1)}
    :return [:pick $1 $startPos $stopPos]}

  # gateway interface-list search function
  :local GwFinder do={
    :local routeISP [/ip route find dst-address=0.0.0.0/0 active=yes];
    :if ([:len $routeISP]=0) do={:return ""}
    :local gwIfc [/ip route get $routeISP vrf-interface]; :local brdgName [/interface bridge find name=$gwIfc];
    :if ([:len $gwIfc]>0 && [:len $brdgName]>0) do={
      :local ipGw [/ip route get $routeISP gateway]; :local macGw [/ip arp get [find address=$ipGw interface=$gwIfc] mac-address];
      :set gwIfc [/interface bridge host get [find mac-address=$macGw] interface]}
    :local ifList [/interface list member find interface=$gwIfc];
    :if ([:len $ifList]!=0) do={:foreach gwList in=$ifList do={:return [/interface list member get $gwList list]}}
    :return ""}

  # function of dangerous IP finder in LOG # $1-prev string $2-curr string $3-next string $4-begin pattern by dangerous IP-addr
  :local IpFinder do={ # $5-end pattern by dangerous IP-addr $6-name of attack $7-nameBlackList $8-timeoutBL $9-logEntry
    # function of converting decimal numbers to hexadecimal
    :local Dec2Hex do={
      :if ($1<10) do={:return "*$1"}
      :local tempNumber $1; :local result ""; :local remainder 0; :local hexTable [:toarray "0,1,2,3,4,5,6,7,8,9,A,B,C,D,E,F"];
      :while ($tempNumber>0) do={
        :set remainder ($tempNumber%16); :set tempNumber [:tonum ($tempNumber>>4)]; :set result (($hexTable->$remainder).$result)}
      :return "*$result"}
    # function of checking correctness IP-address v.4 & blacklisting it # $1-IP-addr $2-nameBlackList $3-timeoutBL $4-logEntry $5-name of attack
    :local IpChk do={
      :if ($1~"((25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)[.]){3}(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)") do={
        :if ([/ip firewall address-list find address=$1 list=$2]="") do={ 
          /ip firewall address-list add address=$1 list=$2 timeout=$3;
          :put "$[/system clock get time]\tAdded in BlackList IP-addr $1 ($5)";
          :if ($4) do={/log warning ">>> Added in BlackList IP: $1 ($5)"}
          :return true}}
      :return false}
    :local prevLen [:len $1]; :local currLen [:len $2]; :local nextLen [:len $3]; :local isDng false; # sign of detected danger
    :if ($currLen=0 or $prevLen!=0 && $nextLen!=0) do={:return $isDng}; # quick exit with incorrect input parameters
    :local bgnPtrn [:len $4]; :local endPtrn [:len $5]; :local dngIp "";
    :local arrPrevId [[:parse $1]]; :local arrCurrId [[:parse $2]]; :local arrNextId [[:parse $3]];
    :local lenPrevId [:len $arrPrevId]; :local lenCurrId [:len $arrCurrId]; :local lenNextId [:len $arrNextId];
    :if ($lenCurrId=0 or $prevLen!=0 && lenPrevId=0 or $nextLen!=0 && $lenNextId=0) do={:return $isDng}; # quick exit when specified string is not found
    :foreach currId in=$arrCurrId do={ # selecting current id string
      :local str [/log get $currId message]; :local strLen [:len $str]; # text of current string
      :if ($strLen<200) do={ # filtering out very long strings
        :local currHexId ("0x".[:pick $currId ([:find $currId "*"] +1) [:len $currId]]); # hex id of current string
        :local prevId "$[$Dec2Hex ([:tonum ($currHexId)] -1)]"; # id of previous string
        :local nextId "$[$Dec2Hex ([:tonum ($currHexId)] +1)]"; # id of next string
        :local findPrev 0; :set findPrev [:len [:find $arrPrevId $prevId]];
        :local findNext 0; :set findNext [:len [:find $arrNextId $nextId]];
        :if ($prevLen=0 && $nextLen=0 && $lenCurrId!=0 or $prevLen!=0 && $nextLen=0 && $findPrev!=0 or $prevLen=0 && $nextLen=!0 && $findNext!=0) do={
          :if ($bgnPtrn!=0) do={:set dngIp [:pick $str ([:find $str $4]+$bgnPtrn) $strLen]} else={:set dngIp $str}; # begin of dangerous IP-addr
          :if ($endPtrn!=0) do={:set dngIp [:pick $dngIp 0 [:find $dngIp $5]]}; # end of dangerous IP-addr
          :if ([$IpChk $dngIp $7 $8 $9 $6]) do={:set isDng true}}}}; # sending suspicious address to verification
    :return $isDng}

  # main body
  :put "$[/system clock get time]\tStart of searching dangerous addresses on '$[/system identity get name]' router";
  :if ([:len $scriptBlckr]=0) do={:set scriptBlckr true}
  :if ($scriptBlckr) do={
    :set scriptBlckr false; :set $timeoutBL [:totime $timeoutBL];
    :if ($extremeScan) do={:put "$[/system clock get time]\tBE CAREFUL!!!!!! Extreme scanning mode is ENABLED!"}
    # checking & installing firewall rules
    :if ($inIfaceList="") do={:set inIfaceList [$GwFinder]; :put "$[/system clock get time]\tVariable 'inIfaceList' is empty -> so value '$inIfaceList' is automatically assigned"}
    :if ([:len [/interface list find name=$inIfaceList]]!=0) do={
      # checking & installing optional firewall rules
      :if ($firewallUsage) do={
        /ip firewall layer7-protocol; find;
        :local cmmnt ""; :local fireL7prot [:toarray {
          "name=CVE-2023-28771 comment=\"IPsec payload missing: SA\" regexp=\";bash -c \\\"(curl|wget) (http:\\\\/\\\\/|)[0-9]+\\\\.[0-9]+\\\\.[0-9]+\\\\.[0-9]\"";}];
        :foreach payLoad in=$fireL7prot do={
          :set $cmmnt [$StrParser [:tostr $payLoad] "comment="];
          :if ([:len [/ip firewall layer7-protocol find comment=$cmmnt]]=0) do={
            :put "$[/system clock get time]\tFirewall layer7 protocol with comment '$cmmnt' not found. Added a regular expression";
            [:parse "/ip firewall layer7-protocol add $payLoad"]}}
        /; /ip firewall filter; find;
        :local firewallFilterRules [:toarray {
          "action=accept chain=input comment=\"defconf: accept established,related,untracked\" connection-state=established,related,untracked";
          "action=drop chain=input comment=\"defconf: drop invalid\" connection-state=invalid";
          "action=accept chain=input comment=\"accept ICMP from external interface\" in-interface-list=$inIfaceList limit=50/5s,2:packet protocol=icmp";
          "action=accept chain=input comment=\"defconf: accept ICMP\" disabled=yes protocol=icmp";
          "action=accept chain=input comment=\"defconf: accept to local loopback (for CAPsMAN)\" dst-address=127.0.0.1";
          "action=accept chain=forward comment=\"defconf: accept in ipsec policy\" ipsec-policy=in,ipsec";
          "action=accept chain=forward comment=\"defconf: accept out ipsec policy\" ipsec-policy=out,ipsec";
          "action=fasttrack-connection chain=forward comment=\"defconf: fasttrack\" connection-state=established,related";
          "action=accept chain=forward comment=\"defconf: accept established,related, untracked\" connection-state=established,related,untracked";
          "action=drop chain=forward comment=\"defconf: drop invalid\" connection-state=invalid";
          "action=drop chain=forward comment=\"defconf: drop all from WAN not DSTNATed\" connection-nat-state=!dstnat connection-state=new in-interface-list=$inIfaceList";
          "action=jump chain=input comment=\"packet analysis for attacks\" in-interface-list=$inIfaceList jump-target=TARPIT protocol=tcp src-address-list=$nameBlackList";
          "action=tarpit chain=TARPIT comment=\"slow down attack to router\" limit=10,10:packet protocol=tcp";
          "action=drop chain=TARPIT comment=\"drop rest of TCP attack\" protocol=tcp";
          "action=drop chain=input comment=\"drop CVE-2023-28771\" connection-state=\"\" dst-port=500 in-interface-list=$inIfaceList layer7-protocol=CVE-2023-28771 protocol=udp";
          "chain=input comment=\"allow DNS request\" in-interface-list=$inIfaceList protocol=udp src-port=53";
          "action=accept chain=input comment=\"accept L2TP/IPSec connections\" connection-state=\"\" dst-port=500,1701,4500 in-interface-list=$inIfaceList protocol=udp";
          "action=accept chain=input comment=\"accept IPSec-esp connections\" connection-state=\"\" in-interface-list=$inIfaceList protocol=ipsec-esp";
          "action=accept chain=input comment=\"accept IPSec-ah connections\" connection-state=\"\" in-interface-list=$inIfaceList protocol=ipsec-ah";
          "action=accept chain=input comment=\"accept SSTP connections\" dst-port=443 in-interface-list=$inIfaceList protocol=tcp";
          "action=accept chain=input comment=\"accept PPTP TCP connections\" connection-state=\"\" dst-port=1723 in-interface-list=$inIfaceList protocol=tcp";
          "action=accept chain=input comment=\"accept PPTP GRE connections\" connection-state=\"\" in-interface-list=$inIfaceList protocol=gre";
          "action=accept chain=input comment=\"accept OVPN connections\" connection-state=\"\" disabled=yes dst-port=1194 in-interface-list=$inIfaceList protocol=tcp";
          "action=accept chain=forward comment=\"accept SIP UDP packets\" disabled=yes dst-port=5060-5061,5160-5161,10000-20000 in-interface-list=$inIfaceList protocol=udp";
          "action=accept chain=forward comment=\"accept SIP TCP packets\" disabled=yes dst-port=5060-5061,5160-5161,10000-20000 in-interface-list=$inIfaceList protocol=tcp";
          "action=accept chain=input comment=\"accept to Minecraft server\" disabled=yes dst-port=25565-25566 in-interface-list=$inIfaceList protocol=tcp";
          "action=jump chain=input comment=\"brute force protection on specified ports\" connection-state=new dst-port=8291 in-interface-list=$inIfaceList jump-target=BruteForce protocol=tcp";
          "action=return chain=BruteForce comment=\"packet analysis for brute force on the specified ports\" dst-limit=4/1m,1,src-address/1m40s";
          "action=add-src-to-address-list chain=BruteForce comment=\"add to BlackList attacker who used specified ports\" address-list=$nameBlackList address-list-timeout=$timeoutBL";
          "action=accept chain=input comment=\"accept WinBox\" dst-port=8291 protocol=tcp in-interface-list=$inIfaceList";
          "action=add-src-to-address-list chain=input comment=\"add to BlackList attacker who used unopened ports\" address-list=$nameBlackList address-list-timeout=$timeoutBL dst-address-type=!broadcast in-interface-list=$inIfaceList";
          "action=drop chain=input comment=\"drop rest of packets\" in-interface-list=$inIfaceList";}];
        :foreach payLoad in=$firewallFilterRules do={
          :set $cmmnt [$StrParser [:tostr $payLoad] "comment="];
          :if ([:len [/ip firewall filter find comment=$cmmnt]]=0) do={
            :put "$[/system clock get time]\tFirewall filter rule with comment '$cmmnt' not found. Added a missing rule";
            [:parse "/ip firewall filter add $payLoad"]}}
        /; /ip firewall raw; find;
        :local firewallRawRules [:toarray {
          "action=drop chain=prerouting comment=\"drop NetBIOS parasit traffic\" dst-port=137,138,139 protocol=udp in-interface-list=$inIfaceList";
          "action=drop chain=prerouting comment=\"drop DNS parasit traffic\" dst-port=53 protocol=udp in-interface-list=$inIfaceList";}];
        :foreach payLoad in=$firewallRawRules do={
          :set $cmmnt [$StrParser [:tostr $payLoad] "comment="];
          :if ([:len [/ip firewall raw find comment=$cmmnt]]=0) do={
            :put "$[/system clock get time]\tFirewall raw rule with comment '$cmmnt' not found. Added a missing rule";
            [:parse "/ip firewall raw add $payLoad"]}}
        /;
      } else={:put "$[/system clock get time]\tATTENTION!!! Firewall rule checking is DISABLED (firewallUsage = false). Recommended to ENABLE (firewallUsage = true)"}
      # checking & installing mandatory firewall rules
      :if ([/ip firewall address-list find list=$nameWhiteList]="") do={/ip firewall address-list add address="input_your_address" list=$nameWhiteList}
      /ip firewall filter;
      :local ruleID ""; :local firewallFlt [find];
      :if ([:len $firewallFlt]=0) do={
        add chain=input comment=$commentRuleWL src-address-list=$nameWhiteList disabled=no;
      } else={
        :if ([find src-address-list=$nameWhiteList]="") do={
          :if ([find action~"passthrough" dynamic=yes]="") do={
            add chain=input comment=$commentRuleWL src-address-list=$nameWhiteList disabled=no place-before=($firewallFlt->0);
          } else={
            :set ruleID [$StrParser [:tostr [get [find action~"passthrough" dynamic=yes]]] ".nextid"];
            :if ($ruleID!="") do={add chain=input comment=$commentRuleWL src-address-list=$nameWhiteList disabled=no place-before=$ruleID}}}}
      :if ([find src-address-list=$nameWhiteList disabled=yes]!="") do={enable [find src-address-list=$nameWhiteList disabled=yes]}
      /; /ip firewall raw;
      :local firewallRaw [find];
      :if ([:len $firewallRaw]=0) do={
        add action=accept chain=prerouting comment=$commentRuleWL src-address-list=$nameWhiteList disabled=no;
      } else={
        :if ([find src-address-list=$nameWhiteList]="") do={
          :if ([find action~"passthrough" dynamic=yes]="") do={
            add action=accept chain=prerouting comment=$commentRuleWL src-address-list=$nameWhiteList disabled=no place-before=($firewallRaw->0);
          } else={
            :set ruleID [$StrParser [:tostr [get [find action~"passthrough" dynamic=yes]]] ".nextid"];
            :if ($ruleID!="") do={add action=accept chain=prerouting comment=$commentRuleWL src-address-list=$nameWhiteList disabled=no place-before=$ruleID}}}}
      :if ([find src-address-list=$nameWhiteList disabled=yes]!="") do={enable [find src-address-list=$nameWhiteList disabled=yes]}
      :if ([find src-address-list=$nameBlackList]="") do={add action=drop chain=prerouting comment=$commentRuleBL src-address-list=$nameBlackList in-interface-list=$inIfaceList protocol=!tcp disabled=yes}
      :if ([find src-address-list=$nameBlackList disabled=yes]!="") do={
        :put "$[/system clock get time]\tATTENTION!!! RAW-rule for blocking dangerous IP-addresses is DISABLED. Check rule properties in 'IP-Firewall-Raw'";
        /log warning "ATTENTION!!! Rule for blocking dangerous IP-addresses is DISABLED.";
        /log warning "Check rule properties in 'IP-Firewall-Raw'."}
      /;
    } else={:put "$[/system clock get time]\tATTENTION!!! Not found list external interfaces named '$inIfaceList'. Check it 'Interfaces-Interface List'. Firewall protection may not work!!!"}
    # stage of analysis device log
    :local isDetected false; :local dataBase {
      {name="login failure";prev="";curr="[/log find topics~\"system\" message~\"login failure for user\"]";next="";bgn="from ";end=" via";};
      {name="denied connect";prev="";curr="[/log find topics~\"warning\" message~\"denied winbox/dude connect from\"]";next="";bgn="from ";end=""};
      {name="L2TP auth failed";prev="";curr="[/log find topics~\"l2tp\" message~\"user\" message~\"authentication failed\"]";next="";bgn="<";end=">"};
      {name="IPsec wrong passwd";prev="";curr="[/log find topics~\"ipsec\" message~\"parsing packet failed, possible cause: wrong password\"]";next="";bgn="";end="parsing"};
      {name="IPSec failed proposal";prev="";curr="[/log find topics~\"ipsec\" message~\"failed to pre-process ph1 packet\"]";next="";bgn="";end=" failed"};
      {name="IPsec ph1 failed due to time up";prev="[/log find topics~\"ipsec\" topics~\"info\" message~\"respond new phase 1 \"]";curr="[/log find topics~\"ipsec\" topics~\"error\" message~\"phase1 negotiation failed due to time up\"]";next="";bgn="<=>";end="["};
      {name="IKEv2 ident not found";prev="[/log find topics~\"ipsec\" topics~\"error\" message~\"identity not found\"]";curr="[/log find topics~\"ipsec\" message~\"killing ike2 SA\"]";next="";bgn="]-";end="["};
      {name="IKEv2 payload missing";prev="";curr="[/log find topics~\"firewall\" message~\"payload missing\"]";next="";bgn="proto UDP, ";end=":"};
      {name="OVPN peer disconn";prev="[/log find topics~\"ovpn\" topics~\"info\" message~\"connection established from\"]";curr="[/log find topics~\"ovpn\" message~\"disconnected <peer disconnected>\"]";next="";bgn="<";end=">"};
      {name="OVPN unknown opcode";prev="[/log find topics~\"ovpn\" topics~\"error\" message~\"unknown opcode received\"]";curr="[/log find topics~\"ovpn\" message~\"disconnected <bad packet received>\"]";next="";bgn="<";end=">"};
      {name="OVPN unknown MSG";prev="[/log find topics~\"ovpn\" topics~\"error\" message~\"unknown msg\" or message~\"msg too short\"]";curr="[/log find topics~\"ovpn\" message~\"TCP connection established from\"]";next="";bgn="from ";end=""};
      {name="PPTP auth failed";prev="";curr="[/log find topics~\"pptp\" message~\"TCP connection established from\"]";next="[/log find topics~\"pptp\" message~\"authentication failed\"]";bgn="from ";end=""};
      {name="TCP conn establ";prev="";curr="[/log find message~\"TCP connection established from\"]";next="";bgn="from ";end="";extr=true};
      {name="IPsec due to time up";prev="";curr="[/log find topics~\"ipsec\" message~\"phase1 negotiation failed due to time up\"]";next="";bgn="<=>";end="[";extr=true}}
    :foreach dangObj in=$dataBase do={
      :if ([:len ($dangObj->"extr")]=0 or $extremeScan=($dangObj->"extr")) do={
        :if [$IpFinder ($dangObj->"prev") ($dangObj->"curr") ($dangObj->"next") ($dangObj->"bgn") ($dangObj->"end") ($dangObj->"name") $nameBlackList $timeoutBL $logEntry] do={:set isDetected true}}}
    # stage of converting Blacklist from dynamic to static
    :if ($staticAddrLst) do={
      /ip firewall address-list;
      :foreach idx in=[find dynamic=yes list=$nameBlackList] do={
        :local ipaddress [get $idx address];
        remove $idx; add list=$nameBlackList address=$ipaddress}}
    # script completion
    :if (!$isDetected) do={:put "$[/system clock get time]\tNo new dangerous IP-addresses were found"};
    :set scriptBlckr true;
  } else={:put "$[/system clock get time]\tScript already being executed..."}
  :put "$[/system clock get time]\tEnd of searching dangerous addresses script";
  } on-error={
  :set scriptBlckr true; :put "Script of blocking dangerous IP addresses worked with errors";
  /log warning "Script of blocking dangerous IP addresses worked with errors"}
