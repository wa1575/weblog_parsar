import string
import sys
import datetime
import numpy as np
import re


import json

#텍스트 출력 [디버깅용]
#label[1] = path 및 args 공격코드 감지 
#label[2_1] = 쿼리문 변수값 길이 이상
#label[2_2] = 쿼리문 변수명 길이 이상 
#label[3] = args 및 ext 내 webshell 시그니처 탐지 
#label[4] = Blind sql injection 시그니처 탐지 
#label[5] = METHOD 이상 탐지  
nowDate = datetime.datetime.now()
sys.stdout = open(nowDate.strftime("%Y-%m-%d_%H%M")+ ".txt","a", -1, 'utf-8')


with open('data.json', encoding="utf-8") as data_file:
    data = json.load(data_file)
with open('dict.json', encoding="utf-8") as dict_file:
    ban = json.load(dict_file)
  
# 근본있게 파일로 만들어서 조회가능하게...
#BAN LIST 출력 
BAN = [ x for x in ban["Attack code"].values()]
resultlist1 = []

# uri 쿼리 변수 길이 필터 - IQR 이상치 검출 알고리즘 적용
def find_upper_lower_bound(data_list):
    temp = sorted(data_list)
    q1, q3 = np.percentile(temp, [25, 75])
    iqr = q3 - q1
    #길이 보정, 만개도 안되는 샘플의 이상치는 보정이 필요함  
    if len(temp) <= 10000:
        lower_bound = q1 - (1.5 * iqr) - 1
        upper_bound = q3 + (1.5 * iqr) + 1

    else : 
        lower_bound = q1 - (1.5 * iqr)
        upper_bound = q3 + (1.5 * iqr)


    return lower_bound, upper_bound


def find_same_name(a):
    # 1단계: 각 이름이 등장한 횟수를 딕셔너리로 만듦
    name_dict = {}
    for name in a:                # 리스트 a에 있는 자료들을 차례로 반복
        if name in name_dict:     # 이름이 name_dict에 있으면
            name_dict[name] += 1  # 등장 횟수를 1 증가

        else:                     # 새 이름이면
            name_dict[name] = 1   # 등장 횟수를 1로 저장

    # 2단계: 만들어진 딕셔너리에서 등장 횟수가 2 이하인 것을 결과에 추가
    result = set()          # 결괏값을 저장할 빈 집합
    for name in name_dict:  # 딕셔너리 name_dict에 있는 자료들을 차례로 반복
        if name_dict[name] <= 2:
            result.add(name)
    return result     

#쿼리문 파싱 결과 사이즈 
args = []
argslen = []
sus_args = {}
pas_args = {}

resultlist2_1 = []
resultlist2_2 = []


# webshell 시그니처 탐지 
shell_func = [ x for x in ban["Webshell code"].values()]
shell_ext = [ x for x in ban["Webshell EXT type"].values()]
resultlist3 = []

#BSQL 인젝션 시느티처 탐지
bsql_inj = [x for x in ban["Blind SQL INJECTION type"].values()]
count = {}
resultlist4 = []

#METHOD 검사
method_detc = [ x for x in ban["Inappropriate Method"].values()]
resultlist5 = []

#json으로 라벨링 결과 저장 
label = {}
p = re.compile('40.')
f = re.compile('.*[.][;]$')

# 1차 분류 개시 
for i in data: 
    IP = data[i]["IP"]
    DATE = data[i]["DATE"]
    METHOD = data[i]["METHOD"]
    PATH = data[i]["PATH"]
    FNAME = data[i]["FNAME"]
    EXT = data[i]["EXT"]
    VERSION = data[i]["VERSION"]
    STATUS = data[i]["STATUS"]
    SIZE = data[i]["SIZE"]
    ARGS = data[i]["ARGS"] # dict라 전환 필요
    #ARGS KEY값 받기 = 변수명 
    argskey = ARGS.keys()
    args.extend(argskey)

    printl = IP+" "+DATE+" "+METHOD+" "+str(PATH)+" "+str(FNAME)+"."+str(EXT)+" "+VERSION+" "+STATUS+" "+SIZE+ " "+str(ARGS)
    if p.match(STATUS) : #상태가 400번대인건 무시
        pass
    else : 
        # Method를 보고 부적절한 양식이 있으면 결과에 추가
        for format in method_detc :
            if METHOD.find(format) > 0 :
                resultlist5.append(printl)

        # BAN 리스트와 비교해서 공격코드가 있으면 결과에 추가하기
        for format in BAN: #=ps%26제외 
            if PATH.find(format) > 0:
                resultlist1.append(printl)
            if str(ARGS).find(format) > 0:
                resultlist1.append(printl)

        # shell 리스트와 비교해서 웹 쉘 시그니처가 있으면 결과에 추가하기
        for format in shell_func:
            if str(ARGS).find(format) > 0:
                resultlist3.append(printl)
            if FNAME == 'cmd' and str(EXT) == 'exe':
                resultlist3.append(printl)
        # .jpg;.cer -> ; 뒷부분을 못읽는 옛날 취약점 공격 
        for format in shell_ext:
            if METHOD == 'POST' or METHOD == 'PUT':
                if f.match(str(FNAME)) and str(EXT).find(format) > 0:
                    resultlist3.append(printl)
        # BlindSQL 리스트와 비교해서 블라인드 SQL 탐지, 우선 시그니처 탐지
        for format in bsql_inj:
            if str(ARGS).find(format) > 0: 
                if STATUS == "500" or STATUS == "200" :
                    resultlist4.append(printl)



# 1차 : 변수명에 따른 분류  
#각 변수명들의 크기 구하기 
for i in range(len(args)) :
    argslen.append(len(args[i]))

#변수명에 관한 딕셔너리 생성
argsdict = dict(zip(args, argslen))

#1차 변수명 필터링 
lower_bound, upper_bound = find_upper_lower_bound(argslen)

# 필터링된 결과를 기반으로 파라미터를 검사할 변수명 선정 
pas_argsdict = {key: value for key, value in argsdict.items() if value > lower_bound and value < upper_bound}

#필터링된 결과를 기반으로 길이만으로 의심할 변수명 선정(코드삽입으로 변수명이 길어진 것들)
#변수명 2차필터-> 각 변수명이 나오는 횟수를 세야 함! 
sus_argsdict = {key: value for key, value in argsdict.items() if value < lower_bound or value > upper_bound}
suslist = []
#변수명 나온 횟수 세고, 의심되는 변수명 찾기 
suslist = find_same_name(args)
#print(suslist)
# 파싱되는 변수명이 길이도 의심스러움 + 횟수까지도 이상함 = 공격코드가 삽입되어 잘못파싱된 것 
sus_argsdict = {key: value for key, value in sus_argsdict.items() if key in suslist }

pas_args_keys = pas_argsdict.keys()
sus_args_keys = sus_argsdict.keys()

valuedict = {}
vdict = {}


cnt = 0

for i in data:
    IP = data[i]["IP"]
    DATE = data[i]["DATE"]
    METHOD = data[i]["METHOD"]
    PATH = data[i]["PATH"]
    FNAME = data[i]["FNAME"]
    EXT = data[i]["EXT"]
    VERSION = data[i]["VERSION"]
    STATUS = data[i]["STATUS"]
    SIZE = data[i]["SIZE"]
    ARGS = data[i]["ARGS"] # dict라 전환 필요
    printl = IP+" "+DATE+" "+METHOD+" "+str(PATH)+" "+str(FNAME)+"."+str(EXT)+" "+VERSION+" "+STATUS+" "+SIZE+ " "+str(ARGS)
    if p.match(STATUS) : #상태가 400번대인건 무시
        pass
    else : 
        # 의심되는 변수명이 있는 경우 분류  ...알고리즘 변경 필요!
        for sus in sus_args_keys :
            if ARGS.get(sus):
                resultlist2_2.append(printl)
 
        #의심되는 변수명들이 없는 경우, 
        #변수명이 정상적인 길이를 가진 경우 변수값 길이 확인
        #해당 변수명을 키값, 각 재어지는 길이 리스트를 벨류로 가지게 만들기!   
        for pas in pas_args_keys :
            if ARGS.get(pas):
                vlan = len(data[i]["ARGS"][pas][0])
                valuedict.setdefault(pas, []).append(vlan)
                v = data[i]["ARGS"][pas][0]
                vdict.setdefault(pas, []).append(v)



#print(vdict)
                    
#같은 키값들끼리 비교 당하면 좋겠다. 
for pas in pas_args_keys :
    lower_bound, upper_bound = find_upper_lower_bound(valuedict[pas])
    #변수가 나온 횟수 세고, 의심되는 변수 찾기 
    suslist = []
    suslist = find_same_name(vdict[pas])
    #print(suslist) 1641 결과 
    #변수길이가 이상한 변수들만 남김 
    valuedict[pas] = {item for item in valuedict[pas] if item < lower_bound or item > upper_bound}
    vdict[pas] = {item for item in vdict[pas] if item in suslist}


#print(vdict)

#라벨링 
for i in data:
    IP = data[i]["IP"]
    DATE = data[i]["DATE"]
    METHOD = data[i]["METHOD"]
    PATH = data[i]["PATH"]
    FNAME = data[i]["FNAME"]
    EXT = data[i]["EXT"]
    VERSION = data[i]["VERSION"]
    STATUS = data[i]["STATUS"]
    SIZE = data[i]["SIZE"]
    ARGS = data[i]["ARGS"] # dict라 전환 필요
    printl = IP+" "+DATE+" "+METHOD+" "+str(PATH)+" "+str(FNAME)+"."+str(EXT)+" "+VERSION+" "+STATUS+" "+SIZE+ " "+str(ARGS)
    if p.match(STATUS) : #상태가 400번대인건 무시
        pass
    else : 
        # 수상한 길이가 있는 변수들만 찾기 
        for pas in pas_args_keys:
            if ARGS.get(pas):
                if len(ARGS[pas][0]) in valuedict[pas] and ARGS[pas][0] in vdict[pas]:
                    resultlist2_1.append(printl)
            else :
                pass


#print(resultlist1)
print(resultlist2_1)
print(resultlist2_2)
#print(resultlist3)
#print(resultlist4)
#print(resultlist5)


#label[1] , Detecting Attack Code
label[1] = { "Detecting Attack Code": resultlist1 }
#label[2], Abnormality detection in Query length, variable name size 
label[2] = { "Abnormality detection in Query Variable length": resultlist2_1 }
#label[3], Abnormality detection in Query length, values size
label[3] = { "Abnormality detection in Query Variable NAME length": resultlist2_2 }
#label[4], Detecting Webshell Signature
label[4] = { "Detecting Webshell Signature": resultlist3 }
#label[5], Detecting Blind SQL Injection 
label[5] = { "Detecting Blind SQL Injection": resultlist4 }
#label[6], Detecting Inappropriate Method 
label[6] = { "Detecting Inappropriate Method": resultlist5 }



with open('label.json', 'w', encoding="utf-8") as fp:
    json.dump(label, fp, ensure_ascii=False, indent="\t")


    

        
