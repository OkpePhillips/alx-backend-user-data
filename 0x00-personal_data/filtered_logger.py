#!/usr/bin/env python3
"""
Module on personal data logging
"""


import re
import logging
import csv
import os
import mysql.connector
from typing import Tuple, List


def filter_datum(fields: List[str], redaction: str, message: str,
                 separator: str) -> str:
    """
    Function to return obfuscated log message
    """
    return re.sub(r'(?:(?<=' + separator + ')|^)(' + '|'.join(
           fields) + ')=.*?(?=' + separator + '|$)', lambda x: x.group(
               1) + '=' + redaction, message)


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
    """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        """
        Initialize RedactingFormatter with a list of fields to be redacted.
        """
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """
        Method to filter values in incoming log records using filter_datum
        """
        record.msg = filter_datum(self.fields, self.REDACTION,
                                  record.msg, self.SEPARATOR)
        return super().format(record)


PII_FIELDS: Tuple[str, str, str, str, str] = ('Name', 'DOB',
                                              'Email', 'Phone',
                                              'Address')


def get_logger() -> logging.Logger:
    """
    function that takes no arguments and returns a logging.Logger object
    """
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)

    stream_handler = logging.StreamHandler()
    formatter = RedactingFormatter(PII_FIELDS)
    stream_handler.setFormatter(formatter)

    logger.addHandler(stream_handler)
    logger.propagate = False

    return logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """
    Function that returns a connector to the database.
    """
    db_username = os.getenv("PERSONAL_DATA_DB_USERNAME", "root")
    db_password = os.getenv("PERSONAL_DATA_DB_PASSWORD", "")
    db_host = os.getenv("PERSONAL_DATA_DB_HOST", "localhost")
    db_name = os.getenv("PERSONAL_DATA_DB_NAME")

    connection = mysql.connector.connect(
        user=db_username,
        password=db_password,
        host=db_host,
        database=db_name
    )

    return connection


def main() -> NoReturn:
    """Entry point to the functions"""
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)

    stream_handler = logging.StreamHandler()
    formatter = RedactingFormatter(('name', 'email', 'phone',
                                    'ssn', 'password'))
    stream_handler.setFormatter(formatter)

    logger.addHandler(stream_handler)
    logger.propagate = False

    connection = get_db()
    cursor = connection.cursor()

    cursor.execute("SELECT * FROM users")
    rows = cursor.fetchall()

    for row in rows:
        logger.info(f"name={row[0]}; email={row[1]}; \
                    phone={row[2]}; ssn={row[3]}; \
                    password={row[4]}; ip={row[5]}; \
                    last_login={row[6]}; user_agent={row[7]}")

    print("Filtered fields:\nname\nemail\nphone\nssn\npassword")


if __name__ == "__main__":
    main()
