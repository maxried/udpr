#!/usr/bin/env python3
# coding=utf-8

"""Logging tools"""

import sys

DEBUGGING: bool = True


def set_debugging(v: bool) -> None:
    """Enable or disable debugging output"""

    global DEBUGGING
    DEBUGGING = v


def l(message: str) -> None:
    """Log a message"""

    print(message, file=sys.stdout)


def e(message: str) -> None:
    """Print an error"""
    print(message, file=sys.stderr)


def d(message: str) -> None:
    """Maybe print debugging info"""
    if DEBUGGING:
        prefixed = 'D: ' + '\nD: '.join(filter(bool, message.split('\n')))
        print(prefixed, file=sys.stdout)
