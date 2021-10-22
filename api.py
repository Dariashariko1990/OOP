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

EMPTY_FIELDS = [None, "", {}]


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

    def validate(self):
        errors = []
        if self.value is None:
            if self.required:
                errors.append(
                    "Не определено значение обязательного поля {}.".format(
                        self.__class__.__name__
                    )
                )
        elif not self.value and not self.nullable:
            errors.append(
                "Значение поля {} не может быть пустым.".format(self.__class__.__name__)
            )
        return not len(errors), errors


class CharField(BaseField):
    """
    Класс текстового поля
    """

    def validate(self):
        valid, errors = super().validate()
        if valid and self.value not in EMPTY_FIELDS:
            if not isinstance(self.value, str):
                errors.append(
                    "Значение поля {} должно быть типом string".format(
                        self.__class__.__name__
                    )
                )
        return not len(errors), errors


class ArgumentsField(BaseField):
    """
    Класс поля аргументов/словаря.
    """

    def validate(self):
        valid, errors = super().validate()
        if valid:
            if not isinstance(self.value, dict):
                errors.append(
                    "Значение поля {} должно быть типом словарь".format(
                        self.__class__.__name__
                    )
                )
        return not len(errors), errors


class EmailField(CharField):
    """
    Класс поля email.
    """

    def validate(self):
        valid, errors = super().validate()
        if valid and self.value not in EMPTY_FIELDS:
            if "@" not in self.value:
                errors.append(
                    "Значение поля {} должно содержать символ '@'.".format(
                        self.__class__.__name__
                    )
                )
        return not len(errors), errors


class PhoneField(BaseField):
    """
    Класс поля телефона.
    """

    def validate(self):
        valid, errors = super().validate()
        if valid and self.value not in EMPTY_FIELDS:
            pattern = r"(\b[7])(\d{10})"
            if isinstance(self.value, str) or isinstance(self.value, int):
                if not re.match(pattern, str(self.value)) or len(str(self.value)) != 11:
                    errors.append(
                        "Значение поля {} введено неверно".format(
                            self.__class__.__name__
                        )
                    )
            else:
                errors.append(
                    "Значение поля {} должно быть типа integer или string".format(
                        self.__class__.__name__
                    )
                )
        return not len(errors), errors


class DateField(BaseField):
    """
    Класс поля даты.
    """

    def validate(self):
        valid, errors = super().validate()
        if valid and self.value not in EMPTY_FIELDS:
            try:
                date_time_obj = datetime.strptime(self.value, "%d.%m.%Y")
            except ValueError:
                errors.append(
                    "Значение поля {} должно быть введено в формате DD.MM.YYYY".format(
                        self.__class__.__name__
                    )
                )
        return not len(errors), errors


class BirthDayField(DateField):
    """
    Класс поля даты рождения.
    """

    def validate(self):
        valid, errors = super().validate()
        if valid and self.value not in EMPTY_FIELDS:
            current_date = datetime.today()
            date_time_obj = datetime.strptime(self.value, "%d.%m.%Y")
            timedelta = current_date - date_time_obj
            if timedelta.days / 365.5 > 70:
                errors.append("С даты рождения должно пройти не более 70 лет")
        return not len(errors), errors


class GenderField(BaseField):
    """
    Класс поля гендера.
    """

    def validate(self):
        valid, errors = super().validate()
        if valid and self.value not in EMPTY_FIELDS:
            if self.value not in GENDERS:
                errors.append(
                    "Значение поля {} может быть только 0, 1, 2".format(
                        self.__class__.__name__
                    )
                )
        return not len(errors), errors


class ClientIDsField(BaseField):
    """
    Класс поля id клиентов.
    """

    def validate(self):
        valid, errors = super().validate()
        if valid and self.value not in EMPTY_FIELDS:
            if not isinstance(self.value, list):
                errors.append(
                    "Значение поля {} должно быть типа list.".format(
                        self.__class__.__name__
                    )
                )
            else:
                if not all([isinstance(el, int) for el in self.value]):
                    errors.append(
                        "Все элементы значения поля {} должны быть INT".format(
                            self.__class__.__name__
                        )
                    )
        return not len(errors), errors


class RequestMeta(type):
    def __new__(mcs, name, bases, attrs, **kwargs):
        request_fields = []
        for key, value in attrs.items():
            if isinstance(value, BaseField):
                request_fields.append({key: value})
        attrs["request_fields"] = request_fields
        cls = super(RequestMeta, mcs).__new__(mcs, name, bases, attrs)
        return cls


class BaseRequest(metaclass=RequestMeta):
    """
    Класс базового request.
    """

    def __init__(self, **kwargs):
        for field in self.request_fields:
            for name, type in field.items():
                type.value = kwargs.get(name)

    def validate_request(self):
        errors = []
        fields = dict(
            (name, getattr(self, name))
            for name in dir(self)
            if not name.startswith("__")
            and not callable((getattr(self, name)))
            and not isinstance(getattr(self, name), list)
        )

        for field in fields:
            if isinstance(fields[field], bool):
                continue
            valid, field_errors = fields[field].validate()
            if not valid:
                errors += field_errors
        return not len(errors), errors


class ClientsInterestsRequest(BaseRequest):
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)

    def ctx(self):
        try:
            return len(self.client_ids.value)
        except TypeError:
            return 0


class OnlineScoreRequest(BaseRequest):
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    def validate_request(self):
        valid, errors = super().validate_request()
        if valid:
            if not (
                (bool(self.first_name.value) and bool(self.last_name.value))
                or (bool(self.phone.value) and bool(self.email.value))
                or (self.gender.value in GENDERS and bool(self.birthday.value))
            ):
                errors.append(
                    "Не найдено не одной обязательной пары: phone-email, first_name-last_name, gender-birthday"
                )
        return not len(errors), errors

    def ctx(self):
        ctx = []
        for field in self.request_fields:
            for field_name, field_type in field.items():
                if field_type.value is not None:
                    ctx.append(field_name)
        return ctx


class MethodRequest(BaseRequest):
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    @property
    def is_admin(self):
        return self.login.value == ADMIN_LOGIN


def check_auth(request):
    if request.is_admin:
        digest = hashlib.sha512(
            (datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT).encode("utf-8")
        ).hexdigest()
    else:
        digest = hashlib.sha512(
            (request.account.value + request.login.value + SALT).encode("utf-8")
        ).hexdigest()
    if digest == request.token.value:
        return True
    return False


def online_score_handler(arguments, is_admin, context, store):
    request = OnlineScoreRequest(**arguments.value)
    valid, errors = request.validate_request()
    context["has"] = request.ctx()
    if not valid:
        return "\n".join(errors), INVALID_REQUEST
    if is_admin:
        return {"score": int(ADMIN_SALT)}, OK
    else:
        score = scoring.get_score(
            store=store,
            phone=request.phone.value,
            email=request.email.value,
            birthday=request.birthday.value,
            gender=request.gender.value,
            first_name=request.first_name.value,
            last_name=request.last_name.value,
        )
        return {"score": score}, OK


def clients_interests_handler(arguments, is_admin, context, store):
    request = ClientsInterestsRequest(**arguments.value)
    valid, errors = request.validate_request()

    if not valid:
        return "\n".join(errors), INVALID_REQUEST
    else:
        context["nclients"] = request.ctx()
    return {
        cid: scoring.get_interests(store=store, cid=cid)
        for cid in request.client_ids.value
    }, OK


METHODS = {
    "online_score": online_score_handler,
    "clients_interests": clients_interests_handler,
}


def method_handler(request, ctx, store):
    r = MethodRequest(**request["body"])
    if request["body"] in EMPTY_FIELDS:
        response = "Empty request"
        return response, INVALID_REQUEST
    valid, errors = r.validate_request()

    if valid:
        if not check_auth(r):
            response = "Authorisation error"
            return response, FORBIDDEN

        if r.method.value not in METHODS.keys():
            response = "Unsupported method"
            return response, NOT_FOUND

        response, code = METHODS[r.method.value](r.arguments, r.is_admin, ctx, store)
        return response, code
    else:
        return "\n".join(errors), INVALID_REQUEST


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {"method": method_handler}
    store = None

    def get_request_id(self, headers):
        return headers.get("HTTP_X_REQUEST_ID", uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
        request = None
        try:
            data_string = self.rfile.read(int(self.headers["Content-Length"]))
            request = json.loads(data_string)
        except:
            code = BAD_REQUEST

        if request:
            path = self.path.strip("/")
            logging.info("%s: %s %s" % (self.path, data_string, context["request_id"]))
            if path in self.router:
                try:
                    response, code = self.router[path](
                        {"body": request, "headers": self.headers}, context, self.store
                    )
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
        self.wfile.write(bytes(json.dumps(r, ensure_ascii=False), "utf-8"))
        return


if __name__ == "__main__":
    op = OptionParser()
    op.add_option("-p", "--port", action="store", type=int, default=8080)
    op.add_option("-l", "--log", action="store", default=None)
    (opts, args) = op.parse_args()

    logging.basicConfig(
        filename="example.log",
        filemode="w",
        level=logging.INFO,
        format="[%(asctime)s] %(levelname).1s %(message)s",
        datefmt="%Y.%m.%d %H:%M:%S",
    )
    server = HTTPServer(("localhost", opts.port), MainHTTPHandler)
    logging.info("Starting server at %s" % opts.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
