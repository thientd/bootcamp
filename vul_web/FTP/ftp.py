from vul_web.models import FTP


def save_config(username, password, host, schedule):
    try:
        ftp_info = FTP(username, password, host, schedule)
        ftp_info.save()
        return True
    except Exception as e:
        return False
