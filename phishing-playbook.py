import imaplib
import email
import re
import uuid
from thehive4py.api import TheHiveApi
from thehive4py.models import Alert, AlertArtifact

# TheHive api login
api = TheHiveApi('http://127.0.0.1:9000', 'API_key', cert=False, organisation="org_name", version=4)

# Function to extract URLs and store them in sets whiting a list [(protocol_1, domain_1, path_1), (protocol_2, domain_2, path_2)]
def get_urls(string):
    urls = re.findall(r'(http|ftp|https):\/\/([\w\-_]+(?:(?:\.[\w\-_]+)+))([\w\-\.,@?^=%&:/~\+#]*[\w\-\@?^=%&/~\+#])?',string)
    return list(set(urls))

# Function to extract Emails and store them in sets whiting a list [(user1, domain_1), (user_2, domain_2)]
def get_emails(string):
    emails = re.findall(r'([a-z0-9\.\-+_]+)@([a-z0-9\.\-+_]+\.[a-z]+)', string)
    return list(set(emails))

# Function to extract IPv4s and store them in a list [IP_1, IP_2]
def get_IPv4s(string):
    IPs = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', string)
    return list(set(IPs))

# login to email account with ssl mode
def login_to_email_account():

    # login creds
    host = 'imap_server'
    username = 'login'
    password = 'password'

    # login process
    mail = imaplib.IMAP4_SSL(host)
    mail.login(username, password)

    return mail

# Function to extract attachment and store them in a folder
attachment_dir = 'D:/attachments'
list_files = []

# Prepare observables
artifacts = []

# get the inbox and parse the wanted fields
def get_inbox(mail):

    # getting the inbox and filtering the needed information
    mail.select("inbox")
    _, search_data = mail.search(None, 'UNSEEN')
    my_messages = []
    for num in search_data[0].split():
        email_data = {}
        _, data = mail.fetch(num, '(RFC822)')
        _, b = data[0]
        email_message = email.message_from_bytes(b)
        email_data['raw'] = str(email_message)
        string = str(email_message)

        # get custom fields from the email
        for header in ['date','from','to','reply-to', 'subject' ]:
            email_data[header] = email_message[header]

        # get html body from the email
        for part in email_message.walk():
            if part.get_content_type() == "text/html":
                body = part.get_payload(decode=True)
                email_data['html'] = body.decode()

        # get attachment from the email
        # for part in email_message.walk():
        #     if part.get_content_maintype() == "multipart":
        #         continue
        #     if part.get('Content-Disposition') is None:
        #         continue

        #     # print(part.get_payload())
        #     # artifacts.append(AlertArtifact(dataType='file', data=part.get_payload()))

        #     fileName = part.get_filename()
        #     list_files.append(fileName)

        #     if bool(fileName):
        #         filePath = os.path.join(attachment_dir, fileName)
        #         with open(filePath, 'wb') as f:
        #             f.write(part.get_payload(decode=True))
        
        email_data['urls'] = get_urls(string)
        email_data['emails'] = get_emails(string)
        email_data['IPs'] = get_IPv4s(string)
        my_messages.append(email_data)
    return my_messages

def create_Analysis(email):

    # adding IP artifacts
    for IP in email['IPs']:
        artifacts.append(AlertArtifact(dataType='ip', data=IP))

    domains = []
    urls = ''
    emails = ''

    # searching for domains in urls
    for url in email['urls']:
        domains.append(url[1])
        urls = urls + str(url[0]) + '://' + str(url[1]) + str(url[2]) + '\n'
    
    # searching for domains in emails
    for mail in email['emails']:
        domains.append(mail[1])
        emails = emails + str(mail[0]) + '@' + str(mail[1]) + '\n'
    
    # remove duplicate domains
    list_domains = list(set(domains))

    # adding domain artifacts
    for domain in list_domains:
        artifacts.append(AlertArtifact(dataType='domain', data=domain))
    
    # adding file artifacts
    for file in list_files:
        artifacts.append(AlertArtifact(dataType='file', data=str(attachment_dir) + '/' + str(file)))

    # Prepare the sample Alert
    sourceRef = str(uuid.uuid4())[0:6]
    alert = Alert(
        title='Phinshing Alert',
        tlp=3,
        tags=['TheHive4Py', 'phishing'],
        description='A phishing email',
        type='external',
        source='Email',
        sourceRef=sourceRef,
        artifacts=artifacts,
        caseTemplate='phishing',
        customFields={   # those are the custom fields I reated in the phishing template I am working with
            "raw": str(email['raw']),
            "date": str(email['date']),
            "from": str(email['from']),
            "to": str(email['to']),
            "reply-to": str(email['reply-to']),
            "subject": str(email['subject']),
            "html": str(email['html']),
            "urls": str(urls),
            "emails": str(emails)
        }
    )

    # Create the alert
    try:
        
        response = api.create_alert(alert)
        alert_id = response.json()['id']
        response = api.promote_alert_to_case(alert_id)
        case_id = response.json()['id']
        response = api.get_case_observables(case_id)
        ids = response.json()
        for obs in ids:
            response = api.run_analyzer('CORTEX', obs['id'], 'VirusTotal_GetReport_3_0')
        print('Alert Created with Success')

    except:
        print("Alert create error")

if __name__ == '__main__':

    mail = login_to_email_account()

    while(True):
        inbox = get_inbox(mail)
        for email in inbox:
            print("Analyze email ...")
            create_Analysis(email)
            print("Analysis done")
