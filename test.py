import ftplib
import schedule
import time

def job():
    session = ftplib.FTP('localhost', 'thientd2', '111111')
    file = open('c.txt', 'rb')  # file to send
    session.storbinary('STOR c.txt', file)  # send the file
    file.close()  # close file and FTP
    session.quit()

schedule.every(1).minutes.do(job)


while True:
    schedule.run_pending()
    time.sleep(1)

