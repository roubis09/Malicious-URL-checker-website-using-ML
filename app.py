import numpy as np
from flask import Flask, request, jsonify, render_template
import pickle
import re
import whois
from urllib.parse import urlparse

app = Flask(__name__)
model = pickle.load(open('lr_model.pkl', 'rb'))


# To check Domain name is included in the url

def abnormal_url_sub(domain,url):
    try:
        try:
            hostname=domain["domain_name"].lower()
        except:
            hostname=domain["domain_name"][0].lower()
    except:
        return 1
    
    #print(hostname)
    match=re.search(hostname,url)
    if match:
        #print(0)
        return 0
    else:
        #print(1)
        return 1
    
def abnormal_url_main(url):
    dns = 0
    try:
        domain_name = whois.whois(url)
        # print(domain_name["domain_name"])
    except:
        dns = 1
        #print('1dns')
        
    if dns == 1:
        return 1
    else:
        return abnormal_url_sub(domain_name,url)
    


def website(site):
    
    # Protocol
    # Protocol
    def Protocol(url):
        x= urlparse(url).scheme
        if x=='http':
            return 1
        elif x=='https':
            return 0
    protocol= Protocol(site)
    
    # length 0f url
    length= len(str(site))
    
    def count(url):
        res= url.count('-')+url.count('@')+url.count('?')+url.count('%')+url.count('.')+url.count('=')+url.count('<')+url.count('>')+url.count('src')+url.count('img')+url.count('script')+url.count('body')
        return res
    count= count(site)
    
    count_www = site.count('www')
    
    def digit_count(url):
        digit= 0
        for i in url:
            if i.isnumeric():
                digit+=1
        return digit
    count_digits= digit_count(site)
    
    # url is ip address or not
    def having_ip_address(url):
        match=re.search('(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  #IPv4
                        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)'  #IPv4 in hexadecimal
                        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}',url)     #Ipv6
        if match:
            #print match.group()
            return 1
        else:
            #print 'No matching pattern found'
            return 0
    use_of_ip= having_ip_address(site)
    
    # To check any shortening service is used or not
    def shortening_service(url):
        match=re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                        'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                        'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                        'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                        'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                        'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                        'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net',url)
        if match:
            return 1
        else:
            return 0

    shortening_service = shortening_service(site)
    
    # HTTPS TOKEN IN URL
    def https_token(url):
        match=re.search('https://|http://',url)
        if match.start(0)==0:
            url=url[match.end(0):]

        match=re.search('http|https',url)
        if match:
            return 1
        else:
            return 0

    https_token = https_token(site)
    
    include_domain= abnormal_url_main(site)
    
    from bs4 import BeautifulSoup
    import urllib.request
    def web_traffic(url):
        try:
            rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml").find("REACH")['RANK']
        except TypeError:
            return 1
        rank= int(rank)
        if (rank<9000000):
            return 0
        else:
            return 2

    web_traffic= web_traffic(site)
    
    # Domain Registration Length
    import whois
    from datetime import datetime
    import time
    def domain_registration_length_sub(domain):
        expiration_date = domain.expiration_date
        today = time.strftime('%Y-%m-%d')
        today = datetime.strptime(today, '%Y-%m-%d')
        
        if expiration_date is None:
            return 0
            
        else:
            if type(expiration_date) is list :
#                 print(expiration_date[0])
                expiration_date= expiration_date[0]
#             print(today[0])
#             return -1             #If it is a type of list then we can't select a single value from list. So,it is regarded as suspected website  
            if type(today) is list:
                today= today[0]
#                 print(today[0])
            
            registration_length = abs((expiration_date - today).days)
    #         if registration_length>3000:
    #             registration_length=0
            return int(registration_length/30)
    #         if registration_length / 365 <= 1:
    #             return 1
    #         else:
    #             return 0

    def domain_registration_length_main(domain):
        dns = 0
        try:
            domain_name = whois.whois(domain)
        except:
            dns = 1

        if dns == 1:
            return 0
        else:
            return domain_registration_length_sub(domain_name)

    registration_length= domain_registration_length_main(site)
    
    
    site_dict= [protocol, length, count, count_www, count_digits, use_of_ip, shortening_service, https_token, include_domain, 
               web_traffic, registration_length]
    
    return site_dict


@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict',methods=['POST'])
def predict():
    '''
    For rendering results on HTML GUI
    '''
    site = request.form.get('url')
    
    if 'http' not in site:
        output= 'Please Enter Full URL with http or https'
    else:
        prediction = model.predict([website(site)])
        if str(prediction[0])=='good':
            output= 'The Site is SAFE'
        else:
            output= 'The Site is suspicious. Beware of this site'

    return render_template('index.html', prediction_text='{}'.format(output))

if __name__ == "__main__":
    app.run(debug=True)