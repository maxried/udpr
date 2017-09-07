#!/usr/bin/env python3
# coding=utf-8

"""Logging tools"""

import sys

DEBUGGING = True


def set_debugging(v):
    global DEBUGGING
    DEBUGGING = v

def l(message):
    """Log a message"""

    print(message, file=sys.stdout)


def e(message):
    """Print an error"""
    print(message, file=sys.stderr)


def d(message):
    """Maybe print debugging info"""
    if DEBUGGING:
        prefixed = 'D: ' + '\nD: '.join(filter(bool, message.split('\n')))
        print(prefixed, file=sys.stdout)
