# Script for searching and blocking dangerous IPv4 addresses
# Script uses ideas by podarok66 evgeniy.demin Virtue tgrba denismikh MMAXSIM andrey-d GregoryGost Chupakabra303 Jotne rextended drPioneer
# https://github.com/drpioneer/MikrotikBlockDangerAddresses/blob/master/danger.rsc
# https://forummikrotik.ru/viewtopic.php?p=70410#p70410
# tested on ROS 6.49.17 & 7.16
# updated 2024/11/01

:global scriptBlckr; # flag of the running script (false=>in progress / true=>idle)
:global timeBlckr;   # time of the last log check (in unix time)
:do {
  :local timeout "8h";  # timeout of blacklist ("1w" "2d" "3h" "4m" "5s" "0w0d8h0m0s" etc...)
  :local wanLst  "";    # name of external interface list ("internet" "WAN" or others=>manual input value; ""=>automatic value selection)
  :local fwUsag  true; # checking & installing firewall rules (false or true)
  :local xtreme  false; # setting log scan level (false=>usual option or true=>extremal option)
  :local logEnt  false; # maintaining log entries (false or true)
  :local stcAdr  false; # converting blacklist from dynamic to static (false or true)
  :local nameBL  "BlockDangerAddress"; # name of blacklist
  :local nameWL  "WhiteList";          # name of whitelist
  :local cmntBL  "dropping dangerous addresses"; # comment for blacklist rule
  :local cmntWL  "white list of IP-addresses";   # comment for whitelist rule
  :local debug   false; # debug mode (true=>is active or false=>is inactive)

  # time translation function to UNIX time # https://forum.mikrotik.com/viewtopic.php?t=75555#p994849
  :global T2UDNG do={ # $1-date/time in any format: "hh:mm:ss","mmm/dd hh:mm:ss","mmm/dd/yyyy hh:mm:ss","yyyy-mm-dd hh:mm:ss","mm-dd hh:mm:ss"
    :local dTime [:tostr $1]; :local yesterDay false; /system clock
    :local cYear [get date]; :if ($cYear~"....-..-..") do={:set $cYear [:pick $cYear 0 4]} else={:set $cYear [:pick $cYear 7 11]}
    :if ([:len $dTime]=10 or [:len $dTime]=11) do={:set $dTime "$dTime 00:00:00"}
    :if ([:len $dTime]=15) do={:set $dTime "$[:pick $dTime 0 6]/$cYear $[:pick $dTime 7 15]"}
    :if ([:len $dTime]=14) do={:set $dTime "$cYear-$[:pick $dTime 0 5] $[:pick $dTime 6 14]"}
    :if ([:len $dTime]=8) do={:if ([:totime $1]>[get time]) do={:set $yesterDay true}; :set $dTime "$[get date] $dTime"}
    :if ([:tostr $1]="") do={:set $dTime ("$[get date] $[get time]")}
    :local vDate [:pick $dTime 0 [:find $dTime " " -1]]; :local vTime [:pick $dTime ([:find $dTime " " -1]+1) [:len $dTime]]
    :local vGmt [get gmt-offset]; :if ($vGmt>0x7FFFFFFF) do={:set $vGmt ($vGmt-0x100000000)}; :if ($vGmt<0) do={:set $vGmt ($vGmt*-1)}
    :local arrMn [:toarray "0,0,31,59,90,120,151,181,212,243,273,304,334"]; :local vdOff [:toarray "0,4,5,7,8,10"]
    :local month [:tonum [:pick $vDate ($vdOff->2) ($vdOff->3)]]
    :if ($vDate~".../../....") do={
      :set $vdOff [:toarray "7,11,1,3,4,6"]
      :set $month ([:find "xxanebarprayunulugepctovecANEBARPRAYUNULUGEPCTOVEC" [:pick $vDate ($vdOff->2) ($vdOff->3)] -1]/2)
      :if ($month>12) do={:set $month ($month-12)}}
    :local year [:pick $vDate ($vdOff->0) ($vdOff->1)]
    :if ((($year-1968)%4)=0) do={:set ($arrMn->1) -1; :set ($arrMn->2) 30}
    :local toTd ((($year-1970)*365)+(($year-1968)>>2)+($arrMn->$month)+([:pick $vDate ($vdOff->4) ($vdOff->5)]-1))
    :if ($yesterDay) do={:set $toTd ($toTd-1)};   # bypassing ROS6.xx time format problem after 00:00:00
    :return (((((($toTd*24)+[:pick $vTime 0 2])*60)+[:pick $vTime 3 5])*60)+[:pick $vTime 6 8]-$vGmt)}

  # time conversion function from UNIX time # https://forum.mikrotik.com/viewtopic.php?p=977170#p977170
  :global U2TDNG do={ # $1-UnixTime $2-OnlyTime
    :local ZeroFill do={:return [:pick (100+$1) 1 3]}
    :local prMntDays [:toarray "0,0,31,59,90,120,151,181,212,243,273,304,334"]
    :local vGmt [:tonum [/system clock get gmt-offset]]
    :if ($vGmt>0x7FFFFFFF) do={:set $vGmt ($vGmt-0x100000000)}
    :if ($vGmt<0) do={:set $vGmt ($vGmt*-1)}
    :local tzEpoch ($vGmt+[:tonum $1])
    :if ($tzEpoch<0) do={:set $tzEpoch 0}; # unsupported negative unix epoch
    :local yearStamp (1970+($tzEpoch/31536000))
    :local tmpLeap (($yearStamp-1968)>>2)
    :if ((($yearStamp-1968)%4)=0) do={:set ($prMntDays->1) -1; :set ($prMntDays->2) 30}
    :local tmpSec ($tzEpoch%31536000)
    :local tmpDays (($tmpSec/86400)-$tmpLeap)
    :if ($tmpSec<(86400*$tmpLeap) && (($yearStamp-1968)%4)=0) do={
      :set $tmpLeap ($tmpLeap-1); :set ($prMntDays->1) 0; :set ($prMntDays->2) 31; :set $tmpDays ($tmpDays+1)}
    :if ($tmpSec<(86400*$tmpLeap)) do={:set $yearStamp ($yearStamp-1); :set $tmpDays ($tmpDays+365)}
    :local mnthStamp 12; :while (($prMntDays->$mnthStamp)>$tmpDays) do={:set $mnthStamp ($mnthStamp-1)}
    :local dayStamp [$ZeroFill (($tmpDays+1)-($prMntDays->$mnthStamp))]
    :local timeStamp (00:00:00+[:totime ($tmpSec%86400)])
    :if ([:len $2]=0) do={:return "$yearStamp/$[$ZeroFill $mnthStamp]/$[$ZeroFill $dayStamp] $timeStamp"} else={:return "$timeStamp"}}

  # search of interface-list gateway
  :local GwFinder do={ # no input parameters
    :local routeISP [/ip route find dst-address=0.0.0.0/0 active=yes]; :if ([:len $routeISP]=0) do={:return ""}
    :set $routeISP "/ip route get $routeISP"
    :local routeGW {"[$routeISP vrf-interface]";"[$routeISP immediate-gw]";"[$routeISP gateway-status]"}
    /interface
    :foreach ifLstMmb in=[list member find] do={
      :local ifIfac [list member get $ifLstMmb interface]; :local ifList [list member get $ifLstMmb list]
      :local brName ""; :do {:set $brName [bridge port get [find interface=$ifIfac] bridge]} on-error={}
      :foreach answer in=$routeGW do={
        :local gw ""; :do {:set $gw [:tostr [[:parse $answer]]]} on-error={}
        :if ([:len $gw]>0 && $gw~$ifIfac or [:len $brName]>0 && $gw~$brName) do={:return $ifList}}}
    :return ""}

  # checking & installing optional firewall rules
  :local ChkFWRul do={ # $1-FWusage $2-wanLst $3-nameBL $4-nameWL $5-cmntRuleBL $6-cmntRuleWL $7-timeout

    # string parsing function 
    :local StrParser do={ # $1-string $2-desired parameter $3-separator
      :if ([:len [:find $1 $2 -1]]=0) do={:return ""}
      :local bgn ([:find $1 $2 -1]+[:len $2] +1); :local end [:find $1 "\"" $bgn]
      :if ([:len $3]!=0) do={
        :if ([:len [:find $1 $3 $bgn]]=0) do={:set $end [:find $1 "\"" $bgn]} else={:set $end [:find $1 $3 $bgn]}}
      :if ($end<$bgn) do={:set $end ($bgn+1)}
      :return [:pick $1 $bgn $end]}

    :global T2UDNG; :global U2TDNG
    :if ($1) do={
      /; /ip firewall layer7-protocol; find; :local cmnt ""
      :local fwL7prt [:toarray {
        "name=CVE-2023-28771 comment=\"IPsec payload missing: SA\" regexp=\";bash -c \\\"(curl|wget) (http:\\\\/\\\\/|)[0-9]+\\\\.[0-9]+\\\\.[0-9]+\\\\.[0-9]\""}]
      :foreach payLoad in=$fwL7prt do={
        :set $cmnt [$StrParser [:tostr $payLoad] "comment="]
        :if ([:len [/ip firewall layer7-protocol find comment=$cmnt]]=0) do={
          [:parse "/ip firewall layer7-protocol add $payLoad"]
          :put "$[$U2TDNG [$T2UDNG]]\tFirewall layer7 protocol with comment '$cmnt' not found.\r\n$[$U2TDNG [$T2UDNG]]\tAdded a regular expression"}}
      /; /ip firewall filter; find
      :local fwFltRul [:toarray {
        "action=accept chain=input comment=\"defconf: accept established,related,untracked\" connection-state=established,related,untracked";
        "action=drop chain=input comment=\"defconf: drop invalid\" connection-state=invalid";
        "action=accept chain=input comment=\"accept ICMP from external interface\" in-interface-list=$2 limit=50/5s,2:packet protocol=icmp";
        "action=accept chain=input comment=\"defconf: accept ICMP\" disabled=yes protocol=icmp";
        "action=accept chain=input comment=\"defconf: accept to local loopback (for CAPsMAN)\" dst-address=127.0.0.1";
        "action=accept chain=forward comment=\"defconf: accept in ipsec policy\" ipsec-policy=in,ipsec";
        "action=accept chain=forward comment=\"defconf: accept out ipsec policy\" ipsec-policy=out,ipsec";
        "action=fasttrack-connection chain=forward comment=\"defconf: fasttrack\" connection-state=established,related";
        "action=accept chain=forward comment=\"defconf: accept established,related, untracked\" connection-state=established,related,untracked";
        "action=drop chain=forward comment=\"defconf: drop invalid\" connection-state=invalid";
        "action=drop chain=forward comment=\"defconf: drop all from WAN not DSTNATed\" connection-nat-state=!dstnat connection-state=new in-interface-list=$2";
        "action=jump chain=input comment=\"packet analysis for attacks\" in-interface-list=$2 jump-target=TARPIT protocol=tcp src-address-list=$3";
        "action=tarpit chain=TARPIT comment=\"slow down attack to router\" limit=10,10:packet protocol=tcp";
        "action=drop chain=TARPIT comment=\"drop rest of TCP attack\" protocol=tcp";
        "action=drop chain=input comment=\"drop CVE-2023-28771\" connection-state=\"\" dst-port=500 in-interface-list=$2 layer7-protocol=CVE-2023-28771 protocol=udp";
        "action=accept chain=input comment=\"allow DNS request\" in-interface-list=$2 protocol=udp src-port=53";
        "action=accept chain=input comment=\"accept L2TP/IPSec connections\" connection-state=\"\" dst-port=500,1701,4500 in-interface-list=$2 protocol=udp";
        "action=accept chain=input comment=\"accept IPSec-esp connections\" connection-state=\"\" in-interface-list=$2 protocol=ipsec-esp";
        "action=accept chain=input comment=\"accept IPSec-ah connections\" connection-state=\"\" in-interface-list=$2 protocol=ipsec-ah";
        "action=accept chain=input comment=\"accept SSTP connections\" dst-port=443 in-interface-list=$2 protocol=tcp";
        "action=accept chain=input comment=\"accept PPTP TCP connections\" connection-state=\"\" dst-port=1723 in-interface-list=$2 protocol=tcp";
        "action=accept chain=input comment=\"accept PPTP GRE connections\" connection-state=\"\" in-interface-list=$2 protocol=gre";
        "action=accept chain=input comment=\"accept OVPN connections\" connection-state=\"\" disabled=yes dst-port=1194 in-interface-list=$2 protocol=tcp";
        "action=accept chain=forward comment=\"accept SIP UDP packets\" disabled=yes dst-port=5060-5061,5160-5161,10000-20000 in-interface-list=$2 protocol=udp";
        "action=accept chain=forward comment=\"accept SIP TCP packets\" disabled=yes dst-port=5060-5061,5160-5161,10000-20000 in-interface-list=$2 protocol=tcp";
        "action=accept chain=input comment=\"accept to Minecraft server\" disabled=yes dst-port=25565-25566 in-interface-list=$2 protocol=tcp";
        "action=jump chain=input comment=\"brute force protection on specified ports\" connection-state=new dst-port=8291 in-interface-list=$2 jump-target=BruteForce protocol=tcp";
        "action=return chain=BruteForce comment=\"packet analysis for brute force on the specified ports\" dst-limit=4/1m,1,src-address/1m40s";
        "action=add-src-to-address-list chain=BruteForce comment=\"add to BlackList attacker who used specified ports\" address-list=$3 address-list-timeout=$7";
        "action=accept chain=input comment=\"accept WinBox\" dst-port=8291 protocol=tcp in-interface-list=$2";
        "action=add-src-to-address-list chain=input comment=\"add to BlackList attacker who used unopened ports\" address-list=$3 address-list-timeout=$7 dst-address-type=!broadcast in-interface-list=$2";
        "action=drop chain=input comment=\"drop rest of packets\" in-interface-list=$2"}];
      :foreach payLoad in=$fwFltRul do={
        :set $cmnt [$StrParser [:tostr $payLoad] "comment="]
        :if ([:len [/ip firewall filter find comment=$cmnt]]=0) do={
          [:parse "/ip firewall filter add $payLoad"]
          :put "$[$U2TDNG [$T2UDNG]]\tFirewall filter rule with comment '$cmnt' not found, added a rule"}}
      /; /ip firewall raw; find
      :local fwRawRul [:toarray {
        "action=drop chain=prerouting comment=\"drop DNS parasit traffic\" dst-port=53 protocol=udp in-interface-list=$2"}]
      :foreach payLoad in=$fwRawRul do={
        :set $cmnt [$StrParser [:tostr $payLoad] "comment="]
        :if ([:len [/ip firewall raw find comment=$cmnt]]=0) do={
          [:parse "/ip firewall raw add $payLoad"]
          :put "$[$U2TDNG [$T2UDNG]]\tFirewall raw rule with comment '$cmnt' not found, added a rule"}}; /
    } else={
      :put "$[$U2TDNG [$T2UDNG]]\tATTENTION!!! Firewall rule checking is DISABLED (fwUsag  false)"
      :put "$[$U2TDNG [$T2UDNG]]\tRecommended to ENABLE (fwUsag  true)"}

    # checking & installing mandatory firewall rules
    :if ([/ip firewall address-list find list=$4]="") do={/ip firewall address-list add address="input_your_address" list=$4}
    /; /ip firewall filter; :local ruleID ""; :local fwFlt [find]
    :if ([:len $fwFlt]=0) do={
      add chain=input comment=$6 src-address-list=$4 disabled=no
    } else={
      :if ([find src-address-list=$4]="") do={
        :if ([find action~"passthrough" dynamic=yes]="") do={
          add chain=input comment=$6 src-address-list=$4 disabled=no place-before=($fwFlt->0)
        } else={
          :set $ruleID [$StrParser [:tostr [get [find action~"passthrough" dynamic=yes]]] ".nextid" ";"]
          :if ($ruleID!="") do={add chain=input comment=$6 src-address-list=$4 disabled=no place-before=$ruleID}}}}
    :if ([find src-address-list=$4 disabled=yes]!="") do={enable [find src-address-list=$4 disabled=yes]}
    /; /ip firewall raw; :local fwRaw [find]
    :if ([:len $fwRaw]=0) do={
      add action=accept chain=prerouting comment=$6 src-address-list=$4 disabled=no
    } else={
      :if ([find src-address-list=$4]="") do={
        :if ([find action~"passthrough" dynamic=yes]="") do={
          add action=accept chain=prerouting comment=$6 src-address-list=$4 disabled=no place-before=($fwRaw->0)
        } else={
          :set $ruleID [$StrParser [:tostr [get [find action~"passthrough" dynamic=yes]]] ".nextid" ";"]
          :if ($ruleID!="") do={add action=accept chain=prerouting comment=$6 src-address-list=$4 disabled=no place-before=$ruleID}}}}
    :if ([find src-address-list=$4 disabled=yes]!="") do={enable [find src-address-list=$4 disabled=yes]}
    :if ([find src-address-list=$3]="") do={add action=drop chain=prerouting comment=$5 src-address-list=$3 in-interface-list=$2 protocol=!tcp disabled=yes}
    :if ([find src-address-list=$3 disabled=yes]!="") do={
      :put "$[$U2TDNG [$T2UDNG]]\tATTENTION!!! RAW-rule for blocking dangerous IPv4 addresses is DISABLED"
      :put "$[$U2TDNG [$T2UDNG]]\tCheck rule properties in 'IP-Firewall-Raw'"
      /log warning "ATTENTION!!! Rule for blocking dangerous IPv4 addresses is DISABLED"
      /log warning "Check rule properties in 'IP-Firewall-Raw'"}; /}

  # device log analysis
  :local Analysis do={ # $1-NameBL $2-TimeoutBL $3-LogEntry $4-ExtremeScan $5-Debug

    # dangerous IPv4 addresses finder in log
    :local IpFinder do={ # $1-PrevStr $2-CurrStr $3-NextStr $4-BeginPtrn $5-EndPtrn $6-NameAttack $7-NameBL $8-TimeoutBL $9-LogEntry $10-Debug

      # checking correctness IPv4 address & blacklisting it
      :local IpCheck do={ # $1-IPaddr $2-NameBL $3-TimeoutBL $4-LogEntry $5-NameAttack $6-Debug
        :global T2UDNG; :global U2TDNG; :global numDNG
        :if ($1~"((25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)[.]){3}(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)") do={
          :if ($6) do={:put ">IpCheck__ip:$1<"}
          :if ([/ip firewall address-list find address=$1 list=$2]="") do={
            :set $numDNG ($numDNG+1)
            /ip firewall address-list add address=$1 list=$2 timeout=$3
            :put "$[$U2TDNG [$T2UDNG]]\tAdded in BlackList IPv4: $1 ($5)"
            :if ($4) do={/log warning ">>> Added in BlackList IPv4: $1 ($5)"}
            :return true}}
        :return false}

      # correcting characters of IPv4 addr
      :local CorrectIpV4 do={
        :if ([:typeof $1]!="str" or [:len $1]=0) do={:return ""}
        :local sym "0123456789."; :local res ""
        :for i from=0 to=([:len $1]-1) do={:local chr [:pick $1 $i]; :if ([:find $sym $chr]>-1) do={:set $res ($res.$chr)}}
        :return [:toip $res]}

      :if ($10) do={:put ">>>IpFinder1__Prev:$1__Curr:$2__Next:$3__Begin:$4__End:$5<<<"}
      :local prevLen [:len $1]; :local currLen [:len $2]; :local nextLen [:len $3]; :local isDng false; # sign of detected danger
      :if ($currLen=0 or $prevLen!=0 && $nextLen!=0) do={:return $isDng}; # quick exit with incorrect input parameters
      /log
      :local arrPrevId ""; :if ($prevLen!=0) do={:set $arrPrevId [find message~$1]}
      :local arrCurrId ""; :if ($currLen!=0) do={:set $arrCurrId [find message~$2]}
      :local arrNextId ""; :if ($nextLen!=0) do={:set $arrNextId [find message~$3]}
      :local lenPrevId [:len $arrPrevId]; :local lenCurrId [:len $arrCurrId]; :local lenNextId [:len $arrNextId]
      :if ($lenCurrId=0 or $prevLen!=0 && lenPrevId=0 or $nextLen!=0 && $lenNextId=0) do={:return $isDng}; # quick exit when specified string is not found
      :global timeBlckr; :global T2UDNG; :local bgnPtrn [:len $4]; :local endPtrn [:len $5]; :local dngIp ""; :local line 5
      :foreach currId in=$arrCurrId do={ # selecting current id string
        :local msg [/log get $currId message]; :local strLen [:len $msg]; :local tim [$T2UDNG [/log get $currId time]]
        :if ($tim>$timeBlckr && $strLen<200) do={ # filtering out old & very long strings
          :local currHexId ("0x".[:pick $currId ([:find $currId "*"] +1) [:len $currId]]); # hex id of current string
          :local findPrev false; :local findNext false; 
          :if ($lenPrevId>0) do={
            :foreach prevId in=$arrPrevId do={ # selecting previous id string
              :local prevHexId ("0x".[:pick $prevId ([:find $prevId "*"] +1) [:len $prevId]]); # hex id of previos string
              :local diff ($currHexId-$prevHexId); :if ($diff>0 && $diff<$line) do={:set $findPrev true}}}
          :if ($lenNextId>0) do={
            :foreach nextId in=$arrNextId do={ # selecting next id string
              :local nextHexId ("0x".[:pick $nextId ([:find $nextId "*"] +1) [:len $nextId]]); # hex id of next string
              :local diff ($nextHexId-$currHexId); :if ($diff>0 && $diff<$line) do={:set $findNext true}}}
          :if ($prevLen=0 && $lenCurrId!=0 && $nextLen=0 or $prevLen!=0 && $nextLen=0 && $findPrev or $prevLen=0 && $nextLen!=0 && $findNext) do={
            :if ($bgnPtrn!=0) do={:set $dngIp [:pick $msg ([:find $msg $4]+$bgnPtrn) $strLen]} else={:set $dngIp $msg}; # begin of dangerous IPv4 addr
            :if ($endPtrn!=0) do={:set $dngIp [:pick $dngIp 0 [:find $dngIp $5]]}; # end of dangerous ipAddr
            :set $dngIp [$CorrectIpV4 $dngIp]; # removing non-IPv4 characters
            :if ($10) do={:put ">>>IpFinder3__dngIp:$dngIp__findPrev:$findPrev__findNext:$findNext<<<"}
            :if ([$IpCheck $dngIp $7 $8 $9 $6 $10]) do={:set $isDng true}; # sending suspicious address to verification
          }}}
      :return $isDng}

    :if ($5) do={:put ">>>>Analysis__NameOfBL:$1__Timeout:$2__LogEntry:$3__ExtremeScan:$4<<<<<"}
    :local isDetected false; :local phraseBase {
      {name="login failure";prev="";curr="login failure for user";next="";bgn="from ";end=" via"};
      {name="denied connect";prev="";curr="denied winbox/dude connect from";next="";bgn="from ";end=""};
      {name="L2TP auth failed";prev="";curr="authentication failed";next="";bgn=" <";end=">"};
      {name="IPsec wrong passwd";prev="";curr="parsing packet failed, possible cause: wrong password";next="";bgn="";end=" parsing"};
      {name="IPSec failed proposal";prev="";curr="failed to pre-process ph1 packet";next="";bgn="";end=" failed"};
      {name="IPsec ph1 failed due to time up";prev="respond new phase 1 ";curr="phase1 negotiation failed due to time up";next="";bgn="<=>";end="["};
      {name="IKEv2 ident not found";prev="identity not found";curr="killing ike2 SA";next="";bgn="]-";end="["};
      {name="IKEv2 payload missing";prev="";curr="payload missing";next="";bgn="proto UDP, ";end=":"};
      {name="OVPN peer disconn";prev="TCP connection established from";curr="disconnected <peer disconnected>";next="";bgn="<";end=">:"};
      {name="OVPN unknown opcode";prev="unknown opcode received";curr="disconnected <bad packet received>";next="";bgn="<";end=">:"};
      {name="OVPN too short MSG";prev="msg too short";curr="TCP connection established from";next="";bgn="from ";end=""};
      {name="OVPN unknown MSG";prev="unknown msg";curr="TCP connection established from";next="";bgn="from ";end=""};
      {name="PPTP auth failed";prev="";curr="TCP connection established from";next="authentication failed";bgn="from ";end=""};
      {name="TCP conn establ";prev="";curr="TCP connection established from";next="";bgn="from ";end="";extr=true};
      {name="IPsec due to time up";prev="";curr="phase1 negotiation failed due to time up";next="";bgn="<=>";end="[";extr=true}}
    :foreach dangObj in=$phraseBase do={
      :if ([:len ($dangObj->"extr")]=0 or $4=($dangObj->"extr")) do={
        :if ([$IpFinder ($dangObj->"prev") ($dangObj->"curr") ($dangObj->"next") ($dangObj->"bgn") ($dangObj->"end") ($dangObj->"name") $1 $2 $3 $5]) do={:set isDetected true}}}
    :return $isDetected}

  # main body
  :global numDNG 0; :local startTime [$T2UDNG]; :local currTime [$U2TDNG $startTime];
  :put "$currTime\tStart of searching dangerous IPv4 addresses on '$[/system identity get name]' router"
  :if ([:len $scriptBlckr]=0) do={:set $scriptBlckr true}
  :if ($scriptBlckr) do={
    :set $scriptBlckr false; :set $timeout [:totime $timeout]
    :if ($debug) do={:put "$[$U2TDNG [$T2UDNG]]\tDebug mode is ENABLED"}
    :if ($xtreme) do={:put "$[$U2TDNG [$T2UDNG]]\tBE CAREFUL!!!!!! Extreme scanning mode is ENABLED!"}
    :if ($wanLst="") do={:set $wanLst [$GwFinder]; :put "$[$U2TDNG [$T2UDNG]]\tVariable 'wanLst' is empty -> so value '$wanLst' is automatically assigned"}
    :if ([:len [/interface list find name=$wanLst]]!=0) do={
      [$ChkFWRul $fwUsag $wanLst $nameBL $nameWL $cmntBL $cmntWL $timeout]
    } else={:put "$[$U2TDNG [$T2UDNG]]\tATTENTION!!! Not found list external interfaces named '$wanLst'."
      :put "$[$U2TDNG [$T2UDNG]]\tCheck it 'Interfaces-Interface List', firewall protection may not work!!!"}
    :if ($timeBlckr=0 or [:len $timeBlckr]=0) do={:put "$[$U2TDNG [$T2UDNG]]\tTime of the last log check was not found"; :set $timeBlckr 0
      } else={:put "$[$U2TDNG [$T2UDNG]]\tTime of the last log check $[$U2TDNG $timeBlckr]"}
    :if ([$Analysis $nameBL $timeout $logEnt $xtreme $debug]) do={
      :put "$[$U2TDNG [$T2UDNG]]\t$numDNG new dangerous IPv4 addresses were found"
    } else={:put "$[$U2TDNG [$T2UDNG]]\tNo new dangerous IPv4 addresses were found"}
    :set $timeBlckr $startTime
    :if ($stcAdr) do={
      /ip firewall address-list
      :foreach idx in=[find dynamic=yes list=$nameBL] do={
        :local ipaddress [get $idx address]; remove $idx; add list=$nameBL address=$ipaddress}}
    :set $currTime [$U2TDNG [$T2UDNG]]
    /system script environment remove [find name~"DNG"]
    :set $scriptBlckr true
  } else={:put "$currTime\tScript already being executed..."}
  :put "$currTime\tEnd of searching dangerous IPv4 addresses script"
} on-error={
  :set $scriptBlckr true
  :put "Script of blocking dangerous IPv4 addresses worked with errors"
  /system script environment remove [find name~"DNG"]
  /log warning "Script of blocking dangerous IPv4 addresses worked with errors"}
# finita la commedia
