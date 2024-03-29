import hashlib
import pickle
import os

POST_FOLDER = 'static/post/'


def sha256(s):
    return hashlib.sha256(s.encode()).hexdigest()


def handle_uploaded_file(note, image):
    with open(POST_FOLDER + note.image_filename, 'wb+') as destination:
        for chunk in image.chunks():
            destination.write(chunk)


def handle_uploaded_file_raw(note, image):
    with open(POST_FOLDER + note.image_filename_raw, 'wb+') as destination:
        for chunk in image.chunks():
            destination.write(chunk)


def save_note(note, image):
    note_file = open(POST_FOLDER + note.internal_title, 'wb')
    note_file.write(pickle.dumps(note))
    note_file.close()
    handle_uploaded_file(note, image)
    handle_uploaded_file_raw(note, image)
    # image.save(POST_FOLDER + note.image_filename)


def unpickle_file(file_name):
    note_file = open(POST_FOLDER + file_name, 'rb')
    return pickle.loads(note_file.read())


class POST(object):
    def __init__(self, name, phone, email, message, image_filename,image_filename_raw, title):
        self.name = name,
        self.phone = phone,
        self.email = email,
        self.message = message,
        self.internal_title = sha256(name + phone + email + image_filename)
        self.image_filename = self.internal_title + '.png'
        self.image_filename_raw = image_filename_raw
        self.title = title
