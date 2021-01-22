#!/usr/bin/env python
# -*- coding: utf-8 -*-

import hashlib
import json
import logging
import logging.config
import re
import uuid
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from optparse import OptionParser

import scoring

SALT = "Otus"
ADMIN_LOGIN = "admin"
ADMIN_SALT = "42"
OK = 200
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
INVALID_REQUEST = 422
INTERNAL_ERROR = 500
ERRORS = {
    BAD_REQUEST: "Bad Request",
    FORBIDDEN: "Forbidden",
    NOT_FOUND: "Not Found",
    INVALID_REQUEST: "Invalid Request",
    INTERNAL_ERROR: "Internal Server Error",
}
UNKNOWN = 0
MALE = 1
FEMALE = 2
GENDERS = {
    UNKNOWN: "unknown",
    MALE: "male",
    FEMALE: "female",
}

EMPTY_FIELDS = [None, '']


class BaseField:
    """
        Класс базового поля
        :param bool required: обязательное. По умлочанию: True
        :param bool nullable: может быть пустым. По умлочанию: False
    """

    def __init__(self, value=None, required=True, nullable=False):
        self.required = required
        self.nullable = nullable
        self.value = value
        self.validate_errors = list()

    def validate(self):
        if self.value is None:
            if self.required:
                self.validate_errors.append(
                    "Не определено значение обязательного поля {}.".format(self.__class__.__name__)
                )
        elif not self.value and not self.nullable:
            self.validate_errors.append(
                "Значение поля {} не может быть пустым.".format(self.__class__.__name__)
            )
        return not len(self.validate_errors)


class CharField(BaseField):
    """
        Класс текстового поля
    """

    def validate(self):
        if super().validate() and self.value not in EMPTY_FIELDS:
            # print('validate CHAR')
            if not isinstance(self.value, str):
                self.validate_errors.append(
                    "Значение поля {} должно быть типом string".format(self.__class__.__name__)
                )
            return not len(self.validate_errors), self.validate_errors


class ArgumentsField(BaseField):
    def validate(self):
        super().validate()
        if not isinstance(self.value, dict):
            self.validate_errors.append(
                "Значение поля {} должно быть типом словарь".format(self.__class__.__name__)
            )
            return print(not len(self.validate_errors), self.validate_errors)


class EmailField(CharField):

    def validate(self):
        if super().validate():
            if "@" not in self.value:
                self.validate_errors.append(
                    "Значение поля {} должно содержать символ '@'.".format(self.__class__.__name__)
                )
            return not len(self.validate_errors), self.validate_errors


class PhoneField(BaseField):

    def validate(self):
        if super().validate() and self.value not in EMPTY_FIELDS:

            pattern = r'(\b[7])(\d{10})'
            if isinstance(self.value, str) or isinstance(self.value, int):
                if not re.match(pattern, str(self.value)) or len(self.value) != 11:
                    self.validate_errors.append(
                        "Значение поля {} введено неверно".format(self.__class__.__name__)
                    )
            else:
                self.validate_errors.append(
                    "Значение поля {} должно быть типа integer или string".format(self.__class__.__name__)
                )
            return not len(self.validate_errors)


class DateField(BaseField):
    def validate(self):
        if super().validate() and self.value not in EMPTY_FIELDS:
            try:
                date_time_obj = datetime.strptime(self.value, '%d.%m.%Y')
            except ValueError:
                self.validate_errors.append(
                    "Значение поля {} должно быть введено в формате DD.MM.YYYY".format(self.__class__.__name__)
                )
            finally:
                return not len(self.validate_errors), self.validate_errors


class BirthDayField(DateField):
    def validate(self):
        if super().validate():
            current_date = datetime.today()
            date_time_obj = datetime.strptime(self.value, '%d.%m.%Y')
            timedelta = current_date - date_time_obj
            if timedelta.days / 365.5 > 70:
                self.validate_errors.append(
                    "С даты рождения должно пройти не более 70 лет"
                )
        return not len(self.validate_errors), self.validate_errors


class GenderField(BaseField):
    def validate(self):
        if super().validate() and self.value not in EMPTY_FIELDS:
            if self.value not in GENDERS:
                self.validate_errors.append(
                    "Значение поля {} может быть только 0, 1, 2".format(self.__class__.__name__)
                )
            return not len(self.validate_errors), self.validate_errors


class ClientIDsField(BaseField):
    def validate(self):
        if super().validate() and self.value not in EMPTY_FIELDS:
            if not isinstance(self.value, list):
                self.validate_errors.append(
                    "Значение поля {} должно быть типа list.".format(self.__class__.__name__)
                )
            else:
                if not all([isinstance(el, int) for el in self.value]):
                    self.validate_errors.append(
                        "Все элементы значения поля {} должны быть INT".format(self.__class__.__name__)
                    )
        return not len(self.validate_errors)


class BaseRequest(object):

    def validate_request(self):
        errors = []
        fields = dict((name, getattr(self, name)) for name in dir(self) if
                      not name.startswith('__') and not callable((getattr(self, name))))
        for field in fields:
            if type(fields[field]) == bool:
                pass
            elif not fields[field].validate():
                errors += fields[field].validate_errors
        return not len(errors), errors


class ClientsInterestsRequest(BaseRequest):
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)

    def __init__(self, **kwargs):
        self.client_ids.value = kwargs.get('client_ids', None)
        self.date.value = kwargs.get('date', None)


class OnlineScoreRequest(BaseRequest):
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    def __init__(self, **kwargs):
        super().__init__()
        self.first_name.value = kwargs.get('first_name', None)
        self.last_name.value = kwargs.get('last_name', None)
        self.email.value = kwargs.get('email', None)
        self.phone.value = kwargs.get('phone', None)
        self.birthday.value = kwargs.get('birthday', None)
        self.gender.value = kwargs.get('gender', None)

    def validate_request(self):
        errors = []
        valid, errors = super().validate_request()
        if valid:
            if not ((bool(self.first_name.value) and bool(self.last_name.value)) or (
                    bool(self.phone.value) and bool(self.email.value)) or (
                            bool(self.gender.value) and bool(self.birthday.value))):
                errors.append(
                    "Не найдено не одной обязательной пары: phone-email, first_name-last_name, gender-birthday"
                )
        return not len(errors), errors

    def get_not_empty_fields(self):
        not_empty_fields = []
        fields = dict((name, getattr(self, name)) for name in dir(self) if
                      not name.startswith('__') and not callable((getattr(self, name))))
        for field in fields:
            if fields[field].value:
                not_empty_fields.append(fields[field].__class__.__name__)
        return not_empty_fields


class MethodRequest(BaseRequest):
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    def __init__(self, **kwargs):
        self.account.value = kwargs.get('account', None)
        self.login.value = kwargs.get('login', None)
        self.token.value = kwargs.get('token', None)
        self.arguments.value = kwargs.get('arguments', None)
        self.method.value = kwargs.get('method', None)

    @property
    def is_admin(self):
        return self.login.value == ADMIN_LOGIN


def check_auth(request):
    if request.is_admin:
        digest = hashlib.sha512((datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT).encode('utf-8')).hexdigest()
    else:
        digest = hashlib.sha512((request.account.value + request.login.value + SALT).encode('utf-8')).hexdigest()
    if digest == request.token.value:
        return True
    return False


def online_score_handler(arguments, is_admin, context, store):
    request = OnlineScoreRequest(**arguments.value)
    valid, errors = request.validate_request()
    context.setdefault('has', request.get_not_empty_fields())
    if not valid:
        return '\n'.join(errors), INVALID_REQUEST
    else:
        if is_admin:
            return {"score": int(ADMIN_SALT)}, OK
        else:
            score = scoring.get_score(store=store,
                                      phone=request.phone.value,
                                      email=request.email.value,
                                      birthday=request.birthday.value,
                                      gender=request.gender.value,
                                      first_name=request.first_name.value,
                                      last_name=request.last_name.value
                                      )
            return {"score": score}, OK


def clients_interests_handler(arguments, is_admin, context, store):
    request = ClientsInterestsRequest(**arguments.value)
    valid, errors = request.validate_request()
    if not valid:
        return '\n'.join(errors), INVALID_REQUEST
    else:
        context["nclients"] = len(request.client_ids.value)
    return {cid: scoring.get_interests(store=store, cid=cid) for cid in request.client_ids.value}, OK


METHODS = {
    "online_score": online_score_handler,
    "clients_interests": clients_interests_handler,
}


def method_handler(request, ctx, store):
    r = MethodRequest(**request["body"])
    valid, errors = r.validate_request()

    if valid:
        if not check_auth(r):
            return ERRORS[FORBIDDEN], FORBIDDEN

        if r.method.value not in METHODS.keys():
            return ERRORS[NOT_FOUND], NOT_FOUND

        response = METHODS[r.method.value](r.arguments, r.is_admin, ctx, store)
        return response
    else:
        return '\n'.join(errors), INVALID_REQUEST


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {
        "method": method_handler
    }
    store = None

    def get_request_id(self, headers):
        return headers.get('HTTP_X_REQUEST_ID', uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
        request = None
        try:
            data_string = self.rfile.read(int(self.headers['Content-Length']))
            request = json.loads(data_string)
        except:
            code = BAD_REQUEST

        if request:
            path = self.path.strip("/")
            logging.info("%s: %s %s" % (self.path, data_string, context["request_id"]))
            if path in self.router:
                try:
                    response, code = self.router[path]({"body": request, "headers": self.headers}, context, self.store)
                except Exception as e:
                    logging.exception("Unexpected error: %s" % e)
                    code = INTERNAL_ERROR
            else:
                code = NOT_FOUND

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if code not in ERRORS:
            r = {"response": response, "code": code}
        else:
            r = {"error": response or ERRORS.get(code, "Unknown Error"), "code": code}
        context.update(r)
        logging.info(context)
        self.wfile.write(bytes(json.dumps(r, ensure_ascii=False), 'utf-8'))
        return


if __name__ == "__main__":
    op = OptionParser()
    op.add_option("-p", "--port", action="store", type=int, default=8080)
    op.add_option("-l", "--log", action="store", default=None)
    (opts, args) = op.parse_args()

    logging.basicConfig(filename='example.log', filemode='w', level=logging.INFO,
                        format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')
    server = HTTPServer(("localhost", opts.port), MainHTTPHandler)
    logging.info("Starting server at %s" % opts.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
