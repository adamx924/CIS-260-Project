# encoding: utf-8
# module _testcapi
# from C:\Users\rmdri\AppData\Local\Programs\Python\Python313\DLLs\_testcapi.pyd
# by generator 1.147
# no doc
# no imports

from .object import object

class DocStringUnrepresentableSignatureTest(object):
    # no doc
    @classmethod
    def classmeth(cls, *args, **kwargs): # real signature unknown
        """ This docstring has a signature with unrepresentable default. """
        pass

    def meth(self, *args, **kwargs): # real signature unknown
        """ This docstring has a signature with unrepresentable default. """
        pass

    def staticmeth(self, *args, **kwargs): # real signature unknown
        """ This docstring has a signature with unrepresentable default. """
        pass

    def with_default(self, *args, **kwargs): # real signature unknown
        """ This instance method has a default parameter value from the module scope. """
        pass

    def __init__(self, *args, **kwargs): # real signature unknown
        pass

    @staticmethod # known case of __new__
    def __new__(*args, **kwargs): # real signature unknown
        """ Create and return a new object.  See help(type) for accurate signature. """
        pass


