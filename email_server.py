import smtplib
import time
import json
from email.message import EmailMessage

def send_mail(email, mail):
	sender = 'notification@homesecurity.com'
	receivers = [email]

	msg = EmailMessage()
	msg.set_content(mail['body'])

	msg['Subject'] = mail['subject']
	msg['To'] = email

	server = smtplib.SMTP('smtp.gmail.com', 587)
	server.ehlo()
	server.starttls()
	server.ehlo()
	server.login("solvers.bot@gmail.com", "1234567890bot")
	server.sendmail(sender, receivers, msg.as_string())
	server.quit()
    
print("Email Server Starting...")

try:
	with open('nicknames.json') as f:
		MacNicknames = json.loads(f.read())
except:
	MacNicknames = {}

num_unknown, num_known = 0, 0

email = "arunbh.y@gmail.com"

while(True):
	mem, nonMem = [], []
	try:
		with open('devices.list') as f:
			deviceList = f.read().split()
	except:
		deviceList = []
	
	for d in deviceList:
		try:
			mem.append(MacNicknames[d.lower()])
		except:
			nonMem.append(d.lower())

	mail = {}
	mail['subject'] = ''

	if (len(mem) != num_known):
		change = len(mem) - num_known
		if (change >= 0):
			change = '+' + str(change)
		mail['subject'] += "Member (" + str(change) + ")"

	if (len(nonMem) != num_unknown):
		if (mail['subject'] != ''):
			mail['subject'] += " | "
		change = len(nonMem) - num_unknown
		if (change >= 0):
			change = '+' + str(change)
		mail['subject'] += "Non-Member (" + str(change) + ")"

	if (mail['subject'] != ''):
		mail['body'] = ''
		if (mem != []):
			mail['body'] += "Memebers\n"
			for w in mem:
				mail['body'] += '\t' + w + '\n'

		if (nonMem != []):
			mail['body'] += "Non-Memebers\n"
			for w in nonMem:
				mail['body'] += '\t' + w + '\n'

		send_mail(email, mail)
		print("Mail Sent to", email, mail['subject'])

	num_unknown, num_known = len(nonMem), len(mem)

	time.sleep(60)
