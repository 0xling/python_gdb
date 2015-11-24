__author__ = 'ling'

from distutils.core import setup
from setuptools import find_packages

setup(
      name="python_gdb",
      version="0.3",
      description="a cure linux debugger",
      author="Ling",
      author_email='ling_pro@163.com',
      url="http://www.github.com/MatrixLing/python_gdb",
      packages=['.'], requires=['termcolor', 'zio'],
      scripts=['tcpserver.py']
)
