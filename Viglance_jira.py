import os 
from datetime import datetime, date, timedelta
import time
import configparser
import urllib.request
import defusedxml.ElementTree as ElementTree
import http.cookiejar
from urllib.error import HTTPError, URLError
import re
from jira import JIRA

BASE_URL = 'https://vigilance.fr'  # Lien Vigilance
LOGIN = ''  # Login de connexion Vigilance disponible dans config.ini
PASSWORD = ''  # Password de connexion Vigilance dans config.ini
XSRF_TOKEN = ''  # Token a Definir
COOKIE = ''  # Cookie a Definir

# use proxy
# proxy = urllib.request.ProxyHandler({'https': 'http://YOURPROXY}) #IP du proxy utilisé
# opener = urllib.request.build_opener(proxy)
# urllib.request.install_opener(opener)

# Connexion JIRA
passwd = "YOURPASSWORD"
jira = JIRA(options={"server": "https://YOURJIRASERVER/", "verify": False}, basic_auth=("YOURACCUNT", passwd))


def main():  # Ouverture de la fonction main 
    global LOGIN, PASSWORD
    os.system('cls' if os.name == 'nt' else 'clear')
    today = date.today()
    config = configparser.ConfigParser()
    config.read('config.ini')#la variable config va lire le document config.ini
    LOGIN = config['credentials']['login'] #la variable LOGIN va prendre la valeur "login" contenu dans le fichier config.ini
    PASSWORD = config['credentials']['password'] #la variable Password va prendre la valeur "login" contenu dans le fichier config.ini

    searchday = today.strftime("%d/%m/%Y")
    finalDate = buildDate(searchday)
    getAlerts(finalDate)


def buildDate(searchday):
    # - If the day is monday -
    if (datetime.strptime(searchday, "%d/%m/%Y").weekday() == 0):
        alertday = datetime.strptime(
            searchday, "%d/%m/%Y") - timedelta(hours=72)  # friday
        return alertday.strftime("%d/%m/%Y")
    else:
        alertday = datetime.strptime(
            searchday, "%d/%m/%Y") - timedelta(hours=24)  # current day -1
        return alertday.strftime("%d/%m/%Y")


def getAlerts(alertday):
    global MAIL_OUTPUT
    if XSRF_TOKEN == '':
        getToken()

    # - Get alerts with CVSS >= 0 && impact score = 1 to 4
    post_data = {
        'clexsrf': XSRF_TOKEN,
        'origine': 1616061255,
        'refchercher': 1,                               # les vulnérabilités
        'critere1_cola': 0,                             # ET
        'critere1_colc__redac': 1,                      # créées (version 1)
        'critere1_colc__cmp': 2,                        # le
        'critere1_colc__date': alertday,                # date
        'critere1_colctype': 10,
        'critere1_colcplan': 1,
        'form_premier_bouton': 'critere1_depreciser',
        'form_plusieurs_boutons': 1,
        'critere2_colc__cmp': 3,                        # CVSS supérieur à (>=)
        'critere2_colc__cvss': 0,                       # 0
        'critere2_colctype': 16,
        'critere2_colcplan': 1,
        'critere3_colc__idxgrav': 10,                   # Gravité = 1, 2, 3 ou 4
        'critere3_colctype': 11,
        'critere3_colcplan': 1,
        'critere4_colctype': 0,
        'critere4_colcplan': 0,
        'bouton_chercher': 'Chercher',
        'complexe': 0,
        'nbcrit': 4,
        'refform_nom': '',
        'refform2': 2147483644
    }
    data = urllib.parse.urlencode(post_data)
    data = data.encode('ascii')  # post data should be bytes

    # - generate url with get values -
    url = "%s" % BASE_URL
    # url = "http://requestb.in/1e2ctbz1"
    get_values = {'gentime': int(time.time())}
    params = urllib.parse.urlencode(get_values)
    headers = {'Cookie': COOKIE,
               'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2907.0 Safari/537.36'}
    req = urllib.request.Request(url + '?' + params, headers=headers)

    # - retrieve url data -
    try:
        with urllib.request.urlopen(req, data) as response:
            html = response.read()
    except HTTPError as e:
        print('The server couldn\'t fulfill the request.')
        exit('Error code: ', e.code, e.headers)
    except URLError as e:
        print('We failed to reach a server.')
        exit('Reason: ', e.reason)

    # - parse data as utf-8 -
    encoding = response.headers.get_content_charset(failobj='utf-8')
    content = html.decode(encoding)

    print(url + '?' + params)

    results = re.compile(
        'https://vigilance.fr/arbre/1/([\d]+)\?gentime=[\d]+&amp;refresu=[\d]+&amp;w=[\d]+')
    bulletins = list(set(results.findall(content)))

    nbvuln = len(bulletins)
    print()
    if nbvuln > 0:
        print('***********************************')
        print('* ' + alertday + ': %-3s' % nbvuln + ' vulnérabilités *')
        print('***********************************')
        print(bulletins)
        for bulletinID in bulletins:
            getInfos(bulletinID)
    else:
        print(alertday + ': Aucune vulnérabilité trouvée.')


def getToken():
    global XSRF_TOKEN, COOKIE

    # - generate url with get values -
    url = "%s/abonne" % BASE_URL
    get_values = {'gentime': int(time.time())}
    params = urllib.parse.urlencode(get_values)
    req = url + '?' + params

    # - generate post data -
    post_data = {
        'AucuneVariablePostee': 1,
        'form_auth_login': LOGIN,
        'form_auth_password': PASSWORD,
        'form_auth_bouton': 'J\'accepte les conditions et accède au service',
        'form_premier_bouton': 'form_auth_bouton'
    }
    data = urllib.parse.urlencode(post_data)
    data = data.encode('ascii')  # post data should be bytes

    # - retrieve url data -
    try:
        with urllib.request.urlopen(req, data) as response:
            html = response.read()
    except HTTPError as e:
        print('The server couldn\'t fulfill the request.')
        print('Error code: ', e.code, e.headers)
        exit()
    except URLError as e:
        print('We failed to reach a server.')
        print('Reason: ', e.reason)
        exit()

    # - verify if logged -
    if 'Votre authentification a ' in str(html):
        print('Mauvais mot de passe Vigil@nce.')
        exit()

    # - get cookie -
    COOKIE = response.getheader('Set-Cookie')
    # print('COOKIE: '+COOKIE)

    # - get xsrf token -
    result = re.search(
        'NAME=\"clexsrf\"(?: ID=\"[^\"]+\")? VALUE=\"([^\"]+)\"', str(html))
    if result.group(1) != '':
        XSRF_TOKEN = result.group(1)
        # print('XSRF_TOKEN: '+XSRF_TOKEN)
    print("Token : ", XSRF_TOKEN)
    print("Cookie : ", COOKIE)


def getInfos(bulletinID):
    # - generate url with get values -
    url = "%s/arbre/6/1/%s" % (BASE_URL, bulletinID)
    get_values = {'gentime': int(time.time())}
    params = urllib.parse.urlencode(get_values)
    headers = {'Cookie': COOKIE,
               'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2907.0 Safari/537.36'}
    req = urllib.request.Request(url + '?' + params, headers=headers)

    print('  [+] Récuperation des infos pour le bulletin #' + bulletinID + ':')

    # - retrieve url data -
    try:
        with urllib.request.urlopen(req) as response:
            html = response.read()
    except HTTPError as e:
        print('The server couldn\'t fulfill the request.')
        print('Error code: ', e.code, e.headers)
        exit()
    except URLError as e:
        print('We failed to reach a server.')
        print('Reason: ', e.reason)
        exit()

    # - parse data as utf-8 -
    encoding = response.headers.get_content_charset(failobj='utf-8')
    content = html.decode(encoding)
    # content = html.decode('iso-8859-1')

    root = ElementTree.fromstring(content)

    titre = root.findall('./titre')[0].text
    ref = root.findall('./referencebulletin')[0].text
    gravite = root.findall('./gravite')[0].text
    desc = root.findall('./description')[0].text
    url = root.findall('./url')[0].text
    competence = root.findall('./competence')[0].text
    cvss3 = root.findall('./cvss_score')[0].text
    # for cvss in root.findall('./cvsss/cvss'):
    #     cvss_vecteur = cvss.find('cvss_vecteur').text
    #     if 'CVSS:3.0' in cvss_vecteur:
    #         cvssv3_score = cvss.find('cvss_score').text
    references = []
    print('      Titre:', titre)
    print('      Gravité:', gravite + '/4')
    print('      Compétence:', competence)
    for reference in root.findall('./references/reference'):
        reference = reference.text
        if reference.startswith('CVE'):
            references.append(reference)
    references = ', '.join(references)
    if references:
        print('      Références:', references)
    consequences = []
    for consequence in root.findall('./consequences/consequence'):
        consequences.append(consequence.text)
    consequences = ', '.join(consequences)
    print('      Conséquence:', consequences)

    composantlist = []
    for composant in root.findall('./composants/composant'):
        composant_nom = composant.find('composant_nom').text
        composant_version = composant.find('composant_version').text
    print('composant', composantlist)

    # Création JIRA
    #For Help : https://jira.readthedocs.io/examples.html#issues 
    creation = {
        "project": "YOURPROJECT",
        "summary": "[VIGILANCE-VUL-" + bulletinID + "] " + titre,
        "issuetype": {"name": "YOURISSUETYPE"},
        'description': '' + desc,
    }
    new_issue = jira.create_issue(fields=creation)

main()