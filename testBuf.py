# encoding: utf-8
# module _testcapi
# from C:\Users\rmdri\AppData\Local\Programs\Python\Python313\DLLs\_testcapi.pyd
# by generator 1.147
# no doc
# no imports

from .object import object

class testBuf(object):
    # no doc
    def __buffer__(self, *args, **kwargs): # real signature unknown
        """ Return a buffer object that exposes the underlying memory of the object. """
        pass

    def __init__(self, *args, **kwargs): # real signature unknown
        pass

    @staticmethod # known case of __new__
    def __new__(*args, **kwargs): # real signature unknown
        """ Create and return a new object.  See help(type) for accurate signature. """
        pass

    def __release_buffer__(self, *args, **kwargs): # real signature unknown
        """ Release the buffer object that exposes the underlying memory of the object. """
        pass

    references = property(lambda self: object(), lambda self, v: None, lambda self: None)  # default



