import string
import sys
import datetime

import json
from collections import OrderedDict

file_data = OrderedDict()

#=ps%26인 경우 제외! //view list 4글자, -> 4글자
file_data["Attack code"]={'netstat':'netstat-nat','etc/passwd':'etc/passwd',
                            '/../ 대입':'/../','ls':'ls%20','널값 요청':'%00','< 입력':'<',
                            '/bin/ls 입력':'/bin/ls','cmd.exe 입력':'cmd.exe','/bin/id 입력':'/bin/id',
                            '/bin/rm 입력':'/bin/rm','wget 명령어 입력':'wget','tftp 명령어 입력':'tftp',
                            'cat 입력':'cat%','echo 입력':'echo','ps 입력':'/ps%','=ps% 입력':'=ps%',
                            'kill 명령':'kill','cc 입력':'cc%','gcc 입력':'gcc%','xterm 입력':'xterm',
                            'chown 명령':'chown','chmod 명령':'chmod','chgrp 명령':'chgrp','chsh 입력':'chsh',
                            '/etc/shadow 입력':'/etc/shadow','/etc/master.passwd 입력':'/etc/master.passwd',
                            '/etc/motd 입력':'/etc/motd','/etc/hosts 입력':'/etc/hosts',
                            '웹서버 환경 파일 정보 검색':'/usr/local/apache/conf/httpd.conf','.htpasswd 입력':'.htpasswd',
                            '/etc/inetd.conf 입력':'/etc/inetd.conf','/etc/inetd.conf 로 원격지 서버권한 획득 시도 감지':'/etc/inetd.conf',
                            '.htaccess 입력':'.htaccess','.htgroup 입력':'.htgroup','error_log 입력':'error_log','access_log 입력':'access_log',
                            '%3f.jsp 입력':'%3f.jsp', 'exec 입력':' exec ', 'alert 입력':'alert'}
#인터넷침해사고대응센터 참고(www.krcert.or.kr)
#웹쉘코드가 실행 가능한 명령어 및 함수 
file_data["Webshell code"] = {'cmd': 'cmd', 'execute':'execute','eval':'eval', 'exec':'exec', 'xp_cmdshell':'xp_cmdshell'}

#웹쉘코드가 실행 가능한 파일 확장자
file_data["Webshell EXT type"] = { 'cer':'cer','asa':'asa', 'cdx':'cdx', 'hta':'hta', 'php3':'php3', 'war':'war'
                                    ,'html':'html', 'htm':'htm'}

#SQL 인젝션 
file_data["Blind SQL INJECTION type"] = { '1==0':'1==0', '1==1':'1==1','1=1':'1=1','1=1--':'1=1--'}

#METHOD 탐지 
file_data["Inappropriate Method"]={"delete":"DELETE", "put":"PUT", "trace":"TRACE", "connect":"CONNECT"}



#print json
print(json.dumps(file_data, ensure_ascii=False, indent="\t"))

with open('dict.json', 'w', encoding="utf-8") as make_file:
    json.dump(file_data, make_file, ensure_ascii=False, indent="\t")
