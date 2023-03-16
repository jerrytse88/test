# coding=utf-8
# encoding=utf8
import sys
reload(sys)
sys.setdefaultencoding('utf8')
import datetime
import os
import sys, getopt
import re
import selenium.webdriver
import urllib2
import re
import ssl
import socket
import logging
import random
import time

gv_logger = logging.getLogger()
gv_logger.setLevel(logging.INFO)  # Log等级总开关
# 第二步，创建一个handler，用于写入日志文件
gv_newFileName = "log.txt"
gv_fh = logging.FileHandler((os.getcwd() + '\\' + gv_newFileName), mode='a')
gv_fh.setLevel(logging.INFO)  # 输出到file的log等级的开关
gv_formatter = logging.Formatter("%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s")
gv_fh.setFormatter(gv_formatter)
gv_logger.addHandler(gv_fh)

undosslcontext = ssl._create_unverified_context()
# 字典中结果形式 key：url
#   {"url"：xxxxx,
# 	"domain"："ddd",
# 	"level":"1"/"2"/"3",
# 	"accessable":"true" / "false",
# 	"return-code": "200"/"304",
#   "info": "xxxxx"	,
# 	"super-url":"",
#   "inner-outer":"inner" / "outer",
#   "sub-url-num":100,
# 	"sub-url":{[],[]}}
gv_url_tag = "url"
gv_domain_tag = "domain"
gv_level_tag = "level"
gv_accessable_tag = "accessable"
gv_return_code_tag = "return-code"
gv_info_tag = "info"
gv_super_url_tag = "super-url"
gv_inner_outer_tag = "inner-outer"
gv_inner_sub_url_num_tag = "inner-sub-url-num"
gv_inner_sub_url_tag = "inner-sub-url"
gv_outer_sub_url_num_tag = "outer-sub-url-num"
gv_outer_sub_url_tag = "outer-sub-url"
gv_inner_value = "inner"
gv_outer_value = "outer"


def gF_LogRecod(msg):
    print(str(msg))
    logging.info(msg)


# 记录日志旧函数
# def gF_LogRecod(msg):
#     print(str(msg))
#     time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S ')
#     newFileName = "log.txt"
#     newFile = os.getcwd() + '\\' + newFileName
#     fwriter = open(newFile, "a")
#     fwriter.write(str(time)+str(msg)+"\n")
#     fwriter.close()


# 获取域名信息
def gF_GetDomainName(webUrl):
    tempUrl = ''
    if webUrl.startswith('http'):
        # 加/ 为了匹配正则表达
        tempUrl = webUrl + '/'
    else:
        tempUrl = "http://" + webUrl + '/'
    # 加HTTP的域名的正则表达式，试试两种正则表达式
    siteAddRegExpList = [
        "^((http://)|(https://))?([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}(/)",
        "(http|ftp|https):\/\/[\w\-_]+(\.[\w\-_]+)+([\w\-\.,@?^=%&:/~\+#]*[\w\-\@?^=%&/~\+#])?",
    ]

    siteAddrStr = ""
    for regExp in siteAddRegExpList:
        siteAdd = re.search(regExp, tempUrl)
        if siteAdd is not None:
            siteAddrStr = siteAdd.group()
            break

    if "" == siteAddrStr:
        # 都没有找到用遍历查找
        starIndex = 0
        endIndex = 0
        starIndex = tempUrl.find("://")
        if starIndex >= 0:
            for i in range(starIndex + 3, len(tempUrl)):
                if tempUrl[i] == "/":
                    endIndex = i
                    break
            if endIndex > starIndex:
                siteAddrStr = tempUrl[starIndex:endIndex]
                siteAddrStr = siteAddrStr + "/"

    domainName = ''
    if "" != siteAddrStr:
        # 取// 和第一个/ 中间的字符
        regExp1 = "\/\/.*?\/"
        domainNameGroup = re.search(regExp1, siteAddrStr)
        if domainNameGroup is not None:
            tempdomainName = domainNameGroup.group()
            if tempdomainName is not None:
                domainName = tempdomainName[2:-1]
    # 返回域名
    # 去端口号
    if '' != domainName:
        if domainName.find("]:") >= 0:
            index = domainName.find("]:")
            domainName = domainName[0:index+1]
        elif domainName.find(":") >= 0:
            index = domainName.find(":")
            domainName = domainName[0:index]

    return domainName


def gF_GetIP(domain):
    try:
        myaddr = socket.getaddrinfo(domain, 80, 0, 0, socket.SOL_TCP)
        return(myaddr[0][4][0])
    except Exception as exp:
        return "get-ip-faied"


class WebPage:
    def __init__(self, firstUrl, innerDomainList, onlyChkDns):
        self.firstUrl = firstUrl
        self.isFirstUrlAccessible = False
        self.secAndThirdSubUrlList = []
        self.historyCheckedUrl = {}
        self.domainIpAddr = ''
        self.domainName = ''
        self.dnsRespons1aTime = -1
        self.dnsRespons4aTime = -1
        self.secUrlNum = 0
        self.secUrlAccessibleNum = 0
        self.secUrlAccessibleRate = 0.0
        self.thirdUrlNum = 0
        self.thirdUrlAccessibleNum = 0
        self.thirdUrlAccessibleRate = 0.0
        self.historyFileName = "history-url.txt"
        self.innerDomainList = innerDomainList
        self.firstUrlDict = {}
        self.secendUrlDict = {}
        self.thirdUrlDict = {}

        self.procHistoryCheckedUrl()  # 先获取已经检查过的
        self.getDomainIpAddr()
        self.getLocalIpAddr()
        # 处理url
        self.procFirstUrl()
        self.procSecendUrl()
        self.procThirdUrl()

        # 检测dns 响应时间，需要本机安装dig命令
        # self.procDnsQureyTime()

    def getDomainIpAddr(self):
        domainName = gF_GetDomainName(self.firstUrl)
        self.domainIpAddr = str(gF_GetIP(domainName))

    def getLocalIpAddr(self):
        try:
            ipadd = ""
            addrs = socket.getaddrinfo(socket.gethostname(), None)
            for item in addrs:
                newipadd = str(item[len(item) - 1])
                ipadd = ipadd + newipadd + "\n"
            gF_LogRecod("get test ip address : \n" + ipadd)
        except Exception as exp:
            gF_LogRecod("get test ip address err !")

    # 关键检查函数
    def checkUrlAccessible(self, superUrl, webUrl, urlLevel):
        checkResult = {}
        # 格式化进行处理
        if webUrl.startswith('http'):
            tempUrl = webUrl
        else:
            tempUrl = "http://" + webUrl

        # 判断是内链还是外链
        isInnerDomain, domainName = self.checkInnerUrl(tempUrl)

        checkResult.update({gv_url_tag: webUrl})
        checkResult.update({gv_domain_tag: domainName})
        checkResult.update({gv_level_tag: urlLevel})
        checkResult.update({gv_super_url_tag: superUrl})
        # 外链直接返回
        if False == isInnerDomain:
            checkResult.update({gv_accessable_tag: False})
            checkResult.update({gv_return_code_tag: ""})
            checkResult.update({gv_info_tag: "outer link"})
            checkResult.update({gv_inner_outer_tag: gv_outer_value})
            checkResult.update({gv_inner_sub_url_num_tag: 0})
            checkResult.update({gv_inner_sub_url_tag: []})
            checkResult.update({gv_outer_sub_url_num_tag: 0})
            checkResult.update({gv_outer_sub_url_tag: []})
            return checkResult

        # 1. 获取是否访问
        try:
            # 模拟几个 agent
            req_header1 = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11 NetworkBench',
                'Accept': 'text/html;q=0.9,*/*;q=0.8',
                'Accept-Charset': 'ISO-8859-1,utf-8;q=0.7,*;q=0.3',
                'Accept-Encoding': 'gzip',
                'Connection': 'close'}

            req_header2 = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.108 Safari/537.36 NetworkBench',
                'Accept': '*/*',
                'Accept-Charset': 'ISO-8859-1,utf-8;q=0.7,*;q=0.3',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'close'}

            req_header3 = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.131 Safari/537.36 NetworkBench',
                'Accept': 'text/html;q=0.9,*/*;q=0.8',
                'Accept-Charset': 'ISO-8859-1,utf-8;q=0.7,*;q=0.3',
                'Accept-Encoding': 'gzip',
                'Connection': 'close'}
            #httpproxy_handler = urllib2.ProxyHandler({"http": "119.57.108.109:53281"})
            #opener = urllib2.build_opener(httpproxy_handler)
            #urllib2.install_opener(opener)

            rHeader = random.choice([req_header1, req_header2, req_header3])
            tempreq = urllib2.Request(tempUrl, None, headers=rHeader)
            # 访问url看是否能访问异常后直接跳出
            returnCodeValue = 0
            returnCodeInfo = ""
            isUrlAccessible = False
            response = urllib2.urlopen(tempreq, context=undosslcontext, timeout=20)
            returnCodeValue = response.getcode()
            returnCodeInfo = response.msg
            # 获取跳转后的值
            redicUrl = response.geturl()

            if returnCodeValue == 200:
                isUrlAccessible = True
            else:
                if (3 == urlLevel or 2 == urlLevel) and ((returnCodeValue / 100) == 2 or (returnCodeValue / 100) == 3):
                    isUrlAccessible = True

            response.close()

        except Exception as exp:
            isUrlAccessible = False
            returnCodeInfo = self.getErrorCode(str(exp))
            gF_LogRecod(str(exp) + "\n" + tempUrl + " can not open!!!")

        checkResult.update({gv_accessable_tag: isUrlAccessible})
        checkResult.update({gv_return_code_tag: returnCodeValue})
        checkResult.update({gv_info_tag: returnCodeInfo})
        checkResult.update({gv_inner_outer_tag: gv_inner_value})

        # 获取子链接
        innerSubNum = 0
        innerSubUrlList = []
        outerSubNum = 0
        outerSubUrlList = []
        if True == isUrlAccessible and (1 == urlLevel or 2 == urlLevel):
            try:
                # 获取url能够访问 超时后获取部分页码内容，有内容算能访问
                g_chromeDriver.get(tempUrl)
                # 如果是 用窗口测试，须要在打开首页窗口时等待用户输入，再进行测试
                if g_useWindowsTest is True and 1 == urlLevel:
                    time.sleep(g_winWaitManualTime)

            except Exception as exp:
                gF_LogRecod(tempUrl + " : get sub url timeout(20s)! may get part page")

            tempsubUrlList = []
            try:
                # 等待1秒
                time.sleep(1)

                # 处理通用 a 标签链接
                urls = g_chromeDriver.find_elements_by_xpath("//a")
                for url in urls:
                    u = url.get_attribute('href')
                    if u is None:
                        continue
                    elif u.startswith('http'):
                        # 获取到一个地址
                        tempsubUrlList.append(u)
                    else:
                        continue

                # 处理特殊标签，请需要特殊标签的省 添加标签 sTagList.append("data-href")
                sTagList = []
                # sTagList.append("data-href") # 特殊标签为 data-href 本处理比较消耗时间，非特殊标签，请不用打开
                for sTag in sTagList:
                    tempTag = "//*[@" + sTag + "]"
                    urls2 = g_chromeDriver.find_elements_by_xpath(tempTag)
                    for url2 in urls2:
                        u2 = url2.get_attribute(sTag)
                        if u2 is None:
                            continue
                        elif u2.startswith('http'):
                            # 获取到一个地址
                            tempsubUrlList.append(u2)
                        else:
                            continue

            except Exception as exp:
                # print(exp)
                gF_LogRecod("find_elements_by_xpath err! may get part sub url")

            # 处理页面内跳转链接 类型jumpPage('https://dx.10086.cn/LkKQCg')
            try:
                htmlContent = g_chromeDriver.page_source
                resultJumpPage = re.findall('jumpPage\(\'(http.*)\'\)', htmlContent)
                for jurl in resultJumpPage:
                    tempsubUrlList.append(jurl)
            except Exception as exp:
                # print(exp)
                gF_LogRecod("find jumpPage err!")

            # Url去重复,分类 , 对已经检查过的url进行去重只保留未检查过的
            for url in tempsubUrlList:
                if url not in self.secAndThirdSubUrlList:
                    self.secAndThirdSubUrlList.append(url)
                    isInnerUrl, domain = self.checkInnerUrl(url)
                    if True == isInnerUrl:
                        innerSubUrlList.append(url)
                        innerSubNum = innerSubNum + 1
                    else:
                        outerSubUrlList.append(url)
                        outerSubNum = outerSubNum + 1

        checkResult.update({gv_inner_sub_url_num_tag: innerSubNum})
        checkResult.update({gv_inner_sub_url_tag: innerSubUrlList})
        checkResult.update({gv_outer_sub_url_num_tag: outerSubNum})
        checkResult.update({gv_outer_sub_url_tag: outerSubUrlList})
        # 将本次能访问的情况写入文件
        if True == isUrlAccessible:
            # 及时写入文件防止测试中断后重测
            self.appendToHistoryFile(str(returnCodeValue), tempUrl)
            self.historyCheckedUrl.update({tempUrl: str(returnCodeValue)})
        # 写入log
        self.resultDicToLog(checkResult)
        return checkResult

    # 检查是否是inner, domain 名称
    def checkInnerUrl(self, webUrl):
        domainName = gF_GetDomainName(webUrl)
        if "" == domainName:
            return False, domainName
        # 特殊列表的先判断为外链排除
        spDomainList = ["chinamobileltd.com", "hk.chinamobile.com"]
        for tempName in spDomainList:
            if domainName.find(tempName) >= 0:
                return False, domainName

        # 根据主机域名判断是否是内链
        for i in range(len(self.innerDomainList)):
            if domainName.find(self.innerDomainList[i]) >= 0 or self.innerDomainList[i].find(domainName) >= 0:
                return True, domainName

        return False, domainName

    # 获取错误码
    def getErrorCode(self, exp):
        rcode = "exception"
        if "timed" in exp and "out" in exp:
            rcode = "timeout"
        elif "getaddrinfo" in exp:
            rcode = "getaddrinfofailed"
        elif "HTTP" in exp and "Error" in exp:
            num = re.findall('\d+', exp)
            if len(num) > 0:
                rcode = str(num[0])
        return rcode

    # 处理第一级别链接
    def procFirstUrl(self):
        gF_LogRecod("processing first url  = " + self.firstUrl + "\n")
        checkResDic = self.checkUrlAccessible("", self.firstUrl, 1)
        # 本字典中只存在一个首页访问的记录
        self.firstUrlDict.update({self.firstUrl:checkResDic})
        # 记录最终结果
        self.isFirstUrlAccessible = False
        if (checkResDic.has_key(gv_accessable_tag)):
            self.isFirstUrlAccessible = checkResDic.get(gv_accessable_tag)

    # 处理第二级别链接
    def procSecendUrl(self):
        for urlkey in self.firstUrlDict.keys():
            tempDict = self.firstUrlDict.get(urlkey)
            # 获取url
            if tempDict.has_key(gv_url_tag):
                urlValue = tempDict.get(gv_url_tag)
            else:
                continue
            # 获取 内链
            if tempDict.has_key(gv_inner_sub_url_tag):
                tempInnerList= tempDict.get(gv_inner_sub_url_tag)
                for i in range(len(tempInnerList)):
                    innerSubUrl = tempInnerList[i]
                    innerResDic = self.checkUrlAccessible(urlValue, innerSubUrl, 2)
                    # 新增二级白名单配置，当二级链接在白名单中，构建可访问结果，子页面设置为0
                    isUseVirtualRes = False
                    newInnerResDic = {}
                    if innerResDic.has_key(gv_accessable_tag) and innerResDic.has_key(gv_inner_outer_tag):
                        accFlag = innerResDic.get(gv_accessable_tag)
                        inOutFlag = str(innerResDic.get(gv_inner_outer_tag))
                        if accFlag is False and inOutFlag.find(gv_inner_value) >= 0:
                            # 检查2级链接是否在白名单中
                            isWhiteRes, strRCode = self.isSecendUrlInWhiteList(innerSubUrl)
                            # 如果在白名单中则构建通过结果
                            if True == isWhiteRes:
                                isUseVirtualRes = True
                                # 构建一个 结果
                                newInnerResDic.update({gv_url_tag: innerSubUrl})
                                newInnerResDic.update({gv_domain_tag: ""})
                                newInnerResDic.update({gv_level_tag: 2})
                                newInnerResDic.update({gv_super_url_tag: urlValue})
                                newInnerResDic.update({gv_accessable_tag: True})
                                newInnerResDic.update({gv_return_code_tag: int(0)})
                                newInnerResDic.update({gv_info_tag: "url is in white list"})
                                newInnerResDic.update({gv_inner_outer_tag: gv_inner_value})
                                newInnerResDic.update({gv_inner_sub_url_num_tag: 0})
                                newInnerResDic.update({gv_inner_sub_url_tag: []})
                                newInnerResDic.update({gv_outer_sub_url_num_tag: 0})
                                newInnerResDic.update({gv_outer_sub_url_tag: []})

                    # 存储 第二级链接的结果
                    if True == isUseVirtualRes:
                        self.secendUrlDict.update({innerSubUrl: newInnerResDic})
                        self.resultDicToLog(newInnerResDic)
                    else:
                        self.secendUrlDict.update({innerSubUrl: innerResDic})
            else:
                continue

    # 处理第三级别链接
    def procThirdUrl(self):
        for urlkey in self.secendUrlDict.keys():
            tempDict = self.secendUrlDict.get(urlkey)
            # 获取url
            if tempDict.has_key(gv_url_tag):
                urlValue = tempDict.get(gv_url_tag)
            else:
                continue
            # 获取 内链
            if tempDict.has_key(gv_inner_sub_url_tag):
                tempInnerList = tempDict.get(gv_inner_sub_url_tag)
                for i in range(len(tempInnerList)):
                    innerSubUrl = tempInnerList[i]
                    # 检查该url是否检查过
                    haveCheckRes, strRCode = self.isThirdUrlHaveCheckedOk(innerSubUrl)
                    innerResDic = {}
                    if False == haveCheckRes:
                        innerResDic = self.checkUrlAccessible(urlValue, innerSubUrl, 3)
                    else:
                        # 构建一个 结果
                        innerResDic.update({gv_url_tag: innerSubUrl})
                        innerResDic.update({gv_domain_tag: ""})
                        innerResDic.update({gv_level_tag: 3})
                        innerResDic.update({gv_super_url_tag: urlValue})
                        innerResDic.update({gv_accessable_tag: True})
                        innerResDic.update({gv_return_code_tag: int(strRCode)})
                        innerResDic.update({gv_info_tag: "last check result"})
                        innerResDic.update({gv_inner_outer_tag: gv_inner_value})
                        innerResDic.update({gv_inner_sub_url_num_tag: 0})
                        innerResDic.update({gv_inner_sub_url_tag: []})
                        innerResDic.update({gv_outer_sub_url_num_tag: 0})
                        innerResDic.update({gv_outer_sub_url_tag: []})
                        # 打印上次的结果
                        self.resultDicToLog(innerResDic)
                    # 存储 第二级链接的结果
                    self.thirdUrlDict.update({innerSubUrl: innerResDic})
            else:
                continue

    # 打印检查的结果
    def resultDicToLog(self, resDic):
        # 判断入参类型
        if isinstance(resDic, dict):
            strValue = ""
            if resDic.has_key(gv_url_tag):
                gF_LogRecod("check url = " + str(resDic.get(gv_url_tag)))
            if resDic.has_key(gv_domain_tag):
                strValue = strValue + ("check result: domain:" + str(resDic.get(gv_domain_tag)))
            if resDic.has_key(gv_level_tag):
                strValue = strValue + (", level:" + str(resDic.get(gv_level_tag)))
            if resDic.has_key(gv_accessable_tag):
                strValue = strValue + (", accessable:" + str(resDic.get(gv_accessable_tag)))
            if resDic.has_key(gv_return_code_tag):
                strValue = strValue + (", return-code:" + str(resDic.get(gv_return_code_tag)))
            if resDic.has_key(gv_info_tag):
                strValue = strValue + (", info:" + str(resDic.get(gv_info_tag)))
            if resDic.has_key(gv_super_url_tag):
                strValue = strValue + (", super-url:" + str(resDic.get(gv_super_url_tag)))
            if resDic.has_key(gv_inner_outer_tag):
                strValue = strValue + (", inner-outer:" + str(resDic.get(gv_inner_outer_tag)))
            if resDic.has_key(gv_inner_sub_url_num_tag):
                strValue = strValue + (", inner-sub-url-num:" + str(resDic.get(gv_inner_sub_url_num_tag)))
            if resDic.has_key(gv_outer_sub_url_num_tag):
                strValue = strValue + (", outer-sub-url-num:" + str(resDic.get(gv_outer_sub_url_num_tag)))
            # 写入文件
            gF_LogRecod(strValue)


    # 已经检查成功的url记录, 第三级不再重新检查，
    def procHistoryCheckedUrl(self):
        newFile = os.getcwd() + '\\' + self.historyFileName
        if (os.path.exists(newFile)):
            freader = open(newFile, "r")
            # 每一行都是返回值,url 如200,https:baidu.com
            urlList = freader.readlines()
            freader.close()
            i = 0
            for i in range(len(urlList)):
                checkedUrl = urlList[i].strip().split(",")
                # 获取返回值和url
                if(2 == len(checkedUrl)):
                    rCode = checkedUrl[0]
                    urlValue = checkedUrl[1]
                    # 更新到集合中,关键字去重
                    self.historyCheckedUrl.update({urlValue: rCode})
        else:
            freader = open(newFile, "a")
            freader.close()

    # 向成功的url中追加记录
    def appendToHistoryFile(self, rCode, url):
        newFile = os.getcwd() + '\\' + self.historyFileName
        fwriter = open(newFile, "a")
        fwriter.write(str(rCode) + ',' + str(url) + "\n")
        fwriter.close()

    # 检查二级链接是否在白名单中，与三级链接共用
    def isSecendUrlInWhiteList(self, url):
        return self.isThirdUrlHaveCheckedOk(url)

    # 检查三级链接是否检查过
    def isThirdUrlHaveCheckedOk(self, url):
        haveChecked = False
        rCode = ""
        if self.historyCheckedUrl.has_key(url):
            lastRCode = self.historyCheckedUrl.get(url)  # 获取返回值
            haveChecked = True  # 文件中只要有记录, 就已经检查通过了
            rCode = str(lastRCode)

        return haveChecked, rCode


    # 生成详细报告
    def generateDetailReport(self, fileFolderPath):
        rstr = r"[\/\\\:\*\?\"\<\>\|]"
        domainName = gF_GetDomainName(self.firstUrl)
        # 去除非法字符 + 时间
        time = datetime.datetime.now().strftime('%Y-%m-%d-%H-%M-%S')
        repFileName = re.sub(rstr, "_", domainName) + "_" + time
        isExists = os.path.exists(fileFolderPath)
        if not isExists:
            repFileNamePath = os.getcwd() + '\\' + repFileName + ".txt"
        else:
            repFileNamePath = fileFolderPath + '\\' + repFileName + ".txt"

        # 创建文件并写入结果
        strLinesList1 = []
        strLinesList1.append("first url:" + self.firstUrl + "\n")
        strLinesList1.append("domain ip:" + self.domainIpAddr + "\n")
        tempFirstDict = {}
        if self.firstUrlDict.has_key(self.firstUrl):
            tempFirstDict = self.firstUrlDict.get(self.firstUrl)

        # 第一级链接结果
        if tempFirstDict.has_key(gv_accessable_tag):
            strLinesList1.append("accessable:" + str(tempFirstDict.get(gv_accessable_tag)) + "\n")
        else:
            strLinesList1.append("accessable: False" + "\n")

        if tempFirstDict.has_key(gv_return_code_tag):
            strLinesList1.append("return code:" + str(tempFirstDict.get(gv_return_code_tag)) + "\n")
        else:
            strLinesList1.append("return code: unkown" + "\n")

        if tempFirstDict.has_key(gv_info_tag):
            strLinesList1.append("info:" + str(tempFirstDict.get(gv_info_tag)) + "\n")
        else:
            strLinesList1.append("info: unkown" + "\n")

        # 第二级 链接结果
        strLinesList2 = []
        secNum = 0
        secInAccOkNum = 0
        secInAccFailNum = 0
        # 内链
        strLinesList2.append("\nsecend inner link url: \n")
        secInnerUrlList = []
        if tempFirstDict.has_key(gv_inner_sub_url_tag):
            secInnerUrlList = tempFirstDict.get(gv_inner_sub_url_tag)

        for i in range(len(secInnerUrlList)):
            secNum = secNum + 1
            strSecIndexInfo = "2-" + str(secNum)
            if self.secendUrlDict.has_key(secInnerUrlList[i]):
                secTempDict = self.secendUrlDict.get(secInnerUrlList[i])
                acRes, strValue = self.resDictToStr(strSecIndexInfo, secTempDict)
                strLinesList2.append(strValue)
                # 统计访问结果
                if acRes == True:
                    secInAccOkNum = secInAccOkNum + 1
                else:
                    secInAccFailNum = secInAccFailNum + 1
            else:
                # 未进行检测的2级链接
                strLinesList2.append(strSecIndexInfo + " uncheck inner url:" + secInnerUrlList[i] + "\n")

        # 外链
        strLinesList2.append("secend outer link url: \n")
        secOuterUrlList = []
        if tempFirstDict.has_key(gv_outer_sub_url_tag):
            secOuterUrlList = tempFirstDict.get(gv_outer_sub_url_tag)
        # 只记录 外联 地址
        for i in range(len(secOuterUrlList)):
            secNum = secNum + 1
            strValueOut2 = "2-" + str(secNum) + " uncheck outer url:" + str(secOuterUrlList[i]) + "\n"
            strLinesList2.append(strValueOut2)

        # 第三级 链接结果
        strLinesList3 = []
        thirdNum = 0
        thirdInAccOkNum = 0
        thirdInAccFailNum = 0
        strLinesList3.append("\nthird link url detail: \n")

        thirdRecdInnerList = []
        thirdRecdOuterList = []
        # 根据 二级 链接的记录进行查找
        for dictValue in  self.secendUrlDict.values():
            # 内部链接
            if dictValue.has_key(gv_inner_sub_url_tag):
                tempInnerList = dictValue.get(gv_inner_sub_url_tag)
                if len(tempInnerList) > 0:
                    thirdRecdInnerList.extend(tempInnerList)
            # 外部链接
            if dictValue.has_key(gv_outer_sub_url_tag):
                tempOuterList = dictValue.get(gv_outer_sub_url_tag)
                if len(tempOuterList) > 0:
                    thirdRecdOuterList.extend(tempOuterList)

        strLinesList3.append("third inner link url detail: \n")
        # 内部链接
        for url in thirdRecdInnerList:
            thirdNum = thirdNum + 1
            strThirdIndexInfo = "3-" + str(thirdNum)
            if (self.thirdUrlDict.has_key(url)):
                tempThirdDict = self.thirdUrlDict.get(url)
                acRes, strValue = self.resDictToStr(strThirdIndexInfo, tempThirdDict)
                strLinesList3.append(strValue)
                if (True == acRes):
                    thirdInAccOkNum = thirdInAccOkNum + 1
                else:
                    thirdInAccFailNum = thirdInAccFailNum + 1
            else:
                strLinesList3.append(strThirdIndexInfo + " uncheck inner url:" + url + "\n")

        # 外部链接
        strLinesList3.append("third outer link(in secend inner link) url detail: \n")
        for url in thirdRecdOuterList:
            thirdNum = thirdNum + 1
            strValueOut3 = "3-" + str(thirdNum) + " uncheck outer url:" + str(url) + "\n"
            strLinesList3.append(strValueOut3)

        # 计算二级总结论
        strLinesList1.append("second inner link：" +
                             " total: " + str(secInAccOkNum + secInAccFailNum) +
                             ", accessable: " + str(secInAccOkNum) + "\n")
        if ((secInAccOkNum + secInAccFailNum) > 0):
            accessibleRate2 = 100 * float(secInAccOkNum) / float(secInAccOkNum + secInAccFailNum)
            strLinesList1.append("second inner link accessable rate: " + str(accessibleRate2) + "%\n")
        else:
            accessibleRate2 = 0.0
            strLinesList1.append("second inner link accessable rate: 0%\n")
        # 计算三级总结论
        strLinesList1.append("third inner link：" +
                             " total: " + str(thirdInAccOkNum + thirdInAccFailNum) +
                             ", accessable: " + str(thirdInAccOkNum) + "\n")
        if ((thirdInAccOkNum + thirdInAccFailNum) > 0):
            accessibleRate3 = 100 * float(thirdInAccOkNum) / float(thirdInAccOkNum + thirdInAccFailNum)
            strLinesList1.append("third inner link accessable rate: " + str(accessibleRate3) + "%\n")
        else:
            accessibleRate3 = 0.0
            strLinesList1.append("third inner link accessable rate: 0%\n")

        # 记录
        self.secUrlNum = (secInAccOkNum + secInAccFailNum)
        self.secUrlAccessibleNum = secInAccOkNum
        self.secUrlAccessibleRate = accessibleRate2
        self.thirdUrlNum = (thirdInAccOkNum + thirdInAccFailNum)
        self.thirdUrlAccessibleNum = thirdInAccOkNum
        self.thirdUrlAccessibleRate = accessibleRate3

        fwriter = open(repFileNamePath, "a")
        fwriter.write("create time：" + datetime.datetime.now().strftime('%Y-%m-%d-%H-%M-%S') + "\n")
        fwriter.writelines(strLinesList1)
        fwriter.writelines(strLinesList2)
        fwriter.writelines(strLinesList3)
        fwriter.close()

    # 处理单个 url 显示字符串
    def resDictToStr(self, strIndex, resDict):
        strValue = str(strIndex)
        accessble = False
        if isinstance(resDict, dict):
            # 是否可访问
            if (resDict.has_key(gv_accessable_tag)):
                strValue = strValue + " accessable:" + str(resDict.get(gv_accessable_tag))
                if (True == resDict.get(gv_accessable_tag)):
                    accessble = True
            else:
                strValue = strValue + " accessable:unkown"

            # 返回值信息
            if (resDict.has_key(gv_return_code_tag)):
                strValue = strValue + ", return code:" + str(resDict.get(gv_return_code_tag))
            else:
                strValue = strValue + ", return code:unkown"

            if (resDict.has_key(gv_info_tag)):
                strValue = strValue + ", info:" + str(resDict.get(gv_info_tag))
            else:
                strValue = strValue + ", info:unkown"

            if (resDict.has_key(gv_url_tag)):
                strValue = strValue + ", url:" + str(resDict.get(gv_url_tag))
            else:
                strValue = strValue + ", url:unkown"

            if (resDict.has_key(gv_super_url_tag)):
                strValue = strValue + ", super-url:" + str(resDict.get(gv_super_url_tag))
            else:
                strValue = strValue + ", super-url:unkown"

        strValue = strValue + "\n"
        return accessble, strValue

    def procDnsQureyTime(self):
        self.domainName, self.dnsRespons1aTime, self.dnsRespons4aTime = self.getDnsQureyTime(self.firstUrl)
        gF_LogRecod("this url domainName,dns1atime,dns4atime = " +
              self.domainName + " ," +
              str(self.dnsRespons1aTime) + " msec," +
              str(self.dnsRespons4aTime) + " msec")

    # 通过dig 命令获取当前网站的DNS反应时延
    def getDnsQureyTime(self,webUrl):
        # 加HTTP的域名的正则表达式，
        siteAddRegExp = "^((http://)|(https://))?([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}(/)"
        tempUrl = ''
        if webUrl.startswith('http'):
            # 加/ 为了匹配正则表达是
            tempUrl = webUrl + '/'
        else:
            tempUrl = "http://" + webUrl + '/'

        siteAdd = re.search(siteAddRegExp, tempUrl)
        domainName = ''
        qurey1aTime = 0
        qurey4aTime = 0
        if siteAdd is not None:
            # 取// 和第一个/ 中间的字符
            regExp1 = "\/\/.*?\/"
            domainNameGroup = re.search(regExp1, siteAdd.group())

            if domainNameGroup is not None:
                tempdomainName = domainNameGroup.group()
                if tempdomainName is not None:
                    domainName = tempdomainName[2:-1]

        time1a = 0
        if  '' !=  domainName:
            # 获取执行结果 -a 结果 每次测试三次
            cmd = "dig " + domainName + " a"
            i = 0
            allTime = 0
            allNum = 0
            for i in range(3):
                backprint = os.popen(cmd)
                cnt = backprint.read()
                tempTime = self.getTimeNum(cnt)
                if tempTime > 0:
                    allNum = allNum+1
                    allTime = allTime + tempTime
            if allNum > 0 :
                qurey1aTime = allTime/allNum
            else:
                qurey1aTime = -1

            cmd = "dig "+ domainName + " aaaa"
            i = 0
            allTime = 0
            allNum = 0
            for i in range(3):
                backprint = os.popen(cmd)
                cnt = backprint.read()
                tempTime = self.getTimeNum(cnt)
                if tempTime > 0:
                    allNum = allNum+1
                    allTime = allTime + tempTime
            if allNum > 0 :
                qurey4aTime = allTime/allNum
            else:
                qurey4aTime = -1

        return domainName, qurey1aTime, qurey4aTime

    # 找出其中的时间
    def getTimeNum(self,strCnt):
        # 先匹配是否有结果，如果没有结果返回-1
        print(strCnt)
        if strCnt.find(";; ANSWER SECTION:") >= 0:
            #说明有结果
            regExpTime = ";; Query time:.*?msec"
            strTime = re.search(regExpTime,strCnt)
            if strTime is not None:
                numRegExp = "[0-9]+"
                timeRes = re.search(numRegExp,strTime.group()).group()

                if timeRes is not None:
                    return int(timeRes)
        else:
            return -1


class WebStationChecker:
    #  webFilePath: 存储web station 的文件
    def __init__(self, webUrlFilePath, onlyChkDns):
        # 存储url文件的路径
        self.webUrlFilePath = webUrlFilePath
        self.onlyChkDns = onlyChkDns
        # 所有的Url列表
        self.allUrlList = []
        self.innerDomainList = []
        self.innerDomainFile = "inner-domain.txt"
        self.getUrlFromFile()
        self.resultFileFolder = self.creatResultFileFolder()
        self.recordFileName = self.createRecordFileName()
        self.getInnerDomainList()

    def creatResultFileFolder(self):
        time = datetime.datetime.now().strftime('%Y-%m-%d-%H-%M-%S')
        fileFolderPath = os.getcwd() + '\\' + time
        isExists = os.path.exists(fileFolderPath)
        if not isExists:
            os.makedirs(fileFolderPath)
        else:
            gF_LogRecod("exist same file folder:" + time)
        return fileFolderPath

    # 创建记录文件
    def createRecordFileName(self):
        newFileName = "weburl-check-results" + '.csv'
        return self.resultFileFolder + '\\' + newFileName

    def getInnerDomainList(self):
        # 先添加几个默认的内链
        self.innerDomainList.append("10086.cn")
        self.innerDomainList.append("chinamobile.com")
        # 本次测试的所有域名都算内链
        for url in self.allUrlList:
            domainName = gF_GetDomainName(url)
            self.innerDomainList.append(domainName)
        # 获取 配置的内链域名
        domainFilePath = os.getcwd() + '\\' + self.innerDomainFile
        isExists = os.path.exists(domainFilePath)
        if isExists is True:
            freader = open(domainFilePath, "r")
            urlList = freader.readlines()
            freader.close()
            for res in urlList:
                if '\xef\xbb\xbf' in res:
                    res = res.replace('\xef\xbb\xbf', '')
                res = res.strip()
                if len(res) > 0 and (res not in self.innerDomainList):
                    self.innerDomainList.append(res)

    # 获取每一行url
    def getUrlFromFile(self):
        gF_LogRecod("\n\n======================new test=========================\n")
        gF_LogRecod("new test,getting url list from " + self.webUrlFilePath)
        if '' != self.webUrlFilePath and os.path.isfile(self.webUrlFilePath):
            freader = open(self.webUrlFilePath, "r")
            tempUrlList = freader.read().splitlines()
            freader.close()
            # 去重
            for url in tempUrlList:
                # 去除第一行的bom码
                if '\xef\xbb\xbf' in url:
                    url = url.replace('\xef\xbb\xbf', '')
                #  去掉空行
                url = url.strip()
                if len(url) > 0 and (url not in self.allUrlList):
                    self.allUrlList.append(url)

            gF_LogRecod("get url num = " + str(len(self.allUrlList)))
        else:
            gF_LogRecod(self.webUrlFilePath + "url file is not a file or not configed!")

    # 处理所有的url
    def procAllUrlAccessibleCheck(self):
        if len(self.allUrlList) == 0:
            return

        # 处理每一个url
        for url in self.allUrlList:
            # 处理每一个首页url
            tempWebPage = WebPage(url, self.innerDomainList, self.onlyChkDns)
            # 生成详细报告
            tempWebPage.generateDetailReport(self.resultFileFolder)
            # 生成统计结果
            self.recordToFile(tempWebPage)

    def recordToFile(self, webPageIns):
        if False == isinstance(webPageIns,WebPage):
            return

        strValue = ''
        strValue = "domain: " + webPageIns.domainName + " "
        strValue = strValue + " dns_1a: " + str(webPageIns.dnsRespons1aTime) + " msec"
        strValue = strValue + " dns_4a: " + str(webPageIns.dnsRespons4aTime) + " msec"
        strValue = strValue + " accessible: " + str(webPageIns.isFirstUrlAccessible) + " "
        strValue = strValue + " inner_sec_num: " + str(webPageIns.secUrlNum) + " "
        strValue = strValue + " sec_as_num: " + str(webPageIns.secUrlAccessibleNum) + " "
        strValue = strValue + " sec_as_rate: " + str(webPageIns.secUrlAccessibleRate) + "% "
        strValue = strValue + " inner_thd_num: " + str(webPageIns.thirdUrlNum) + " "
        strValue = strValue + " thd_as_num: " + str(webPageIns.thirdUrlAccessibleNum) + " "
        strValue = strValue + " thd_as_rate: " + str(webPageIns.thirdUrlAccessibleRate) + "% "
        strValue = strValue + " url: " + webPageIns.firstUrl + " \n"
        #  写入文件中
        try:
            fwriter = open(self.recordFileName, "a")
            fwriter.write(strValue)
            fwriter.close()
        except Exception as exp:
            print(str(exp))


if __name__ == '__main__':

    urlfile = ''
    cfgedFile = 0
    cfgedDnsCheck = 0
    winwait = ''
    g_useWindowsTest = False
    g_winWaitManualTime = 10

    try:
        opts, args = getopt.getopt(sys.argv[1:], "-h-d-f:-w:", ["help", "dns", "urlfile=", "winwait="])
    except getopt.GetoptError:
        print 'cramler.py -f <urlfile>'
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print '-f <urlfile>  # urlfile -- the url list txt file of web station, one url one line. '
            print '-w <waittime> # waittime -- use open windows test and waittime is wait manual operation time,secends'
            print '-d            # -- check dns response time only. '

            sys.exit()
        elif opt in ("-f", "--urlfile"):
            urlfile = arg
            cfgedFile = 1
        elif opt in ("-d", "--dns"):
            cfgedDnsCheck = 1
        elif opt in("-w", "--winwait"):
            winwait = arg
            restr = "[0-9]\d*"
            waitTimeGroup = re.search(restr, winwait)
            if waitTimeGroup is not None:
                g_useWindowsTest = True
                g_winWaitManualTime = 10
                waitTime = waitTimeGroup.group()
                if int(waitTime) < 10:
                    g_winWaitManualTime = 10
                elif int(waitTime) > 300:
                    g_winWaitManualTime = 300
                elif int(waitTime) >= 10 and int(waitTime) <= 300:
                    g_winWaitManualTime = int(waitTime)

                print ("use open window test model, wait manual operation time(s):" + str(g_winWaitManualTime))

        else:
            cfgedFile = 0
            cfgedDnsCheck = 0

        urlfilePath = ''
    if 1 == cfgedFile:
        if os.path.exists(urlfile):
            urlfilePath = urlfile
        elif os.path.exists(os.getcwd()+'\\' + urlfile):
            urlfilePath = os.getcwd()+'\\' + urlfile
        else:
            print('url file not exist!')
            sys.exit()

    print (datetime.datetime.now().strftime('%Y-%m-%d-%H-%M-%S'))


    #  调用chrome浏览器并后台运行
    g_chromeOption = selenium.webdriver.ChromeOptions()
    if False == g_useWindowsTest:
        g_chromeOption.add_argument('headless')
    g_chromeDriver = selenium.webdriver.Chrome(chrome_options=g_chromeOption)
    g_chromeDriver.set_page_load_timeout(20)
    g_chromeDriver.implicitly_wait(5)

    checker = WebStationChecker(urlfilePath, cfgedDnsCheck)
    checker.procAllUrlAccessibleCheck()

    g_chromeDriver.quit()
    print (datetime.datetime.now().strftime('%Y-%m-%d-%H-%M-%S'))


# 修改记录
# 2020-5-27 全面更新结果展现形式，对每个主页行成一个详细报告，删除faild流程，对二三级去重
# 2020-6-4 增加对部分网站有端口号的特殊处理,对获取
# 2020-8-4 增加手动输入用户名密码部分
# 2020-10-22 2、3级链接 2xx、3xx都认为正常
# 2020-10-27 排除香港链接、添加2级白名单功能、增加特殊标签处理