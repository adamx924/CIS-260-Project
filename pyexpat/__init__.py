# encoding: utf-8
# module pyexpat
# from C:\Users\rmdri\AppData\Local\Programs\Python\Python313\DLLs\pyexpat.pyd
# by generator 1.147
""" Python wrapper for Expat parser. """

# imports
import pyexpat.errors as errors # <module 'pyexpat.errors'>
import pyexpat.model as model # <module 'pyexpat.model'>

# Variables with simple values

EXPAT_VERSION = 'expat_2.6.3'

native_encoding = 'UTF-8'

XML_PARAM_ENTITY_PARSING_ALWAYS = 2
XML_PARAM_ENTITY_PARSING_NEVER = 0

XML_PARAM_ENTITY_PARSING_UNLESS_STANDALONE = 1

# functions

def ErrorString(*args, **kwargs): # real signature unknown
    """ Returns string error for given number. """
    pass

def ParserCreate(*args, **kwargs): # real signature unknown
    """ Return a new XML parser object. """
    pass

# classes

class ExpatError(Exception):
    # no doc
    def __init__(self, *args, **kwargs): # real signature unknown
        pass

    __weakref__ = property(lambda self: object(), lambda self, v: None, lambda self: None)  # default
    """list of weak references to the object"""



error = ExpatError


class XMLParserType(object):
    """ XML parser """
    def ExternalEntityParserCreate(self, *args, **kwargs): # real signature unknown
        """ Create a parser for parsing an external entity based on the information passed to the ExternalEntityRefHandler. """
        pass

    def GetBase(self, *args, **kwargs): # real signature unknown
        """ Return base URL string for the parser. """
        pass

    def GetInputContext(self, *args, **kwargs): # real signature unknown
        """
        Return the untranslated text of the input that caused the current event.
        
        If the event was generated by a large amount of text (such as a start tag
        for an element with many attributes), not all of the text may be available.
        """
        pass

    def GetReparseDeferralEnabled(self, *args, **kwargs): # real signature unknown
        """ Retrieve reparse deferral enabled status; always returns false with Expat <2.6.0. """
        pass

    def Parse(self, *args, **kwargs): # real signature unknown
        """
        Parse XML data.
        
        `isfinal' should be true at end of input.
        """
        pass

    def ParseFile(self, *args, **kwargs): # real signature unknown
        """ Parse XML data from file-like object. """
        pass

    def SetBase(self, *args, **kwargs): # real signature unknown
        """ Set the base URL for the parser. """
        pass

    def SetParamEntityParsing(self, *args, **kwargs): # real signature unknown
        """
        Controls parsing of parameter entities (including the external DTD subset).
        
        Possible flag values are XML_PARAM_ENTITY_PARSING_NEVER,
        XML_PARAM_ENTITY_PARSING_UNLESS_STANDALONE and
        XML_PARAM_ENTITY_PARSING_ALWAYS. Returns true if setting the flag
        was successful.
        """
        pass

    def SetReparseDeferralEnabled(self, *args, **kwargs): # real signature unknown
        """ Enable/Disable reparse deferral; enabled by default with Expat >=2.6.0. """
        pass

    def UseForeignDTD(self, *args, **kwargs): # real signature unknown
        """
        Allows the application to provide an artificial external subset if one is not specified as part of the document instance.
        
        This readily allows the use of a 'default' document type controlled by the
        application, while still getting the advantage of providing document type
        information to the parser. 'flag' defaults to True if not provided.
        """
        pass

    def __init__(self, *args, **kwargs): # real signature unknown
        pass

    AttlistDeclHandler = property(lambda self: object(), lambda self, v: None, lambda self: None)  # default

    buffer_size = property(lambda self: object(), lambda self, v: None, lambda self: None)  # default

    buffer_text = property(lambda self: object(), lambda self, v: None, lambda self: None)  # default

    buffer_used = property(lambda self: object(), lambda self, v: None, lambda self: None)  # default

    CharacterDataHandler = property(lambda self: object(), lambda self, v: None, lambda self: None)  # default

    CommentHandler = property(lambda self: object(), lambda self, v: None, lambda self: None)  # default

    CurrentByteIndex = property(lambda self: object(), lambda self, v: None, lambda self: None)  # default

    CurrentColumnNumber = property(lambda self: object(), lambda self, v: None, lambda self: None)  # default

    CurrentLineNumber = property(lambda self: object(), lambda self, v: None, lambda self: None)  # default

    DefaultHandler = property(lambda self: object(), lambda self, v: None, lambda self: None)  # default

    DefaultHandlerExpand = property(lambda self: object(), lambda self, v: None, lambda self: None)  # default

    ElementDeclHandler = property(lambda self: object(), lambda self, v: None, lambda self: None)  # default

    EndCdataSectionHandler = property(lambda self: object(), lambda self, v: None, lambda self: None)  # default

    EndDoctypeDeclHandler = property(lambda self: object(), lambda self, v: None, lambda self: None)  # default

    EndElementHandler = property(lambda self: object(), lambda self, v: None, lambda self: None)  # default

    EndNamespaceDeclHandler = property(lambda self: object(), lambda self, v: None, lambda self: None)  # default

    EntityDeclHandler = property(lambda self: object(), lambda self, v: None, lambda self: None)  # default

    ErrorByteIndex = property(lambda self: object(), lambda self, v: None, lambda self: None)  # default

    ErrorCode = property(lambda self: object(), lambda self, v: None, lambda self: None)  # default

    ErrorColumnNumber = property(lambda self: object(), lambda self, v: None, lambda self: None)  # default

    ErrorLineNumber = property(lambda self: object(), lambda self, v: None, lambda self: None)  # default

    ExternalEntityRefHandler = property(lambda self: object(), lambda self, v: None, lambda self: None)  # default

    intern = property(lambda self: object(), lambda self, v: None, lambda self: None)  # default

    namespace_prefixes = property(lambda self: object(), lambda self, v: None, lambda self: None)  # default

    NotationDeclHandler = property(lambda self: object(), lambda self, v: None, lambda self: None)  # default

    NotStandaloneHandler = property(lambda self: object(), lambda self, v: None, lambda self: None)  # default

    ordered_attributes = property(lambda self: object(), lambda self, v: None, lambda self: None)  # default

    ProcessingInstructionHandler = property(lambda self: object(), lambda self, v: None, lambda self: None)  # default

    SkippedEntityHandler = property(lambda self: object(), lambda self, v: None, lambda self: None)  # default

    specified_attributes = property(lambda self: object(), lambda self, v: None, lambda self: None)  # default

    StartCdataSectionHandler = property(lambda self: object(), lambda self, v: None, lambda self: None)  # default

    StartDoctypeDeclHandler = property(lambda self: object(), lambda self, v: None, lambda self: None)  # default

    StartElementHandler = property(lambda self: object(), lambda self, v: None, lambda self: None)  # default

    StartNamespaceDeclHandler = property(lambda self: object(), lambda self, v: None, lambda self: None)  # default

    UnparsedEntityDeclHandler = property(lambda self: object(), lambda self, v: None, lambda self: None)  # default

    XmlDeclHandler = property(lambda self: object(), lambda self, v: None, lambda self: None)  # default



# variables with complex values

expat_CAPI = None # (!) real value is '<capsule object "pyexpat.expat_CAPI" at 0x000001FDB8974270>'

features = [
    (
        'sizeof(XML_Char)',
        1,
    ),
    (
        'sizeof(XML_LChar)',
        1,
    ),
    (
        'XML_DTD',
        0,
    ),
    (
        'XML_CONTEXT_BYTES',
        1024,
    ),
    (
        'XML_NS',
        0,
    ),
    (
        'XML_BLAP_MAX_AMP',
        100,
    ),
    (
        'XML_BLAP_ACT_THRES',
        8388608,
    ),
    (
        'XML_GE',
        0,
    ),
]

version_info = (
    2,
    6,
    3,
)

__loader__ = None # (!) real value is '<_frozen_importlib_external.ExtensionFileLoader object at 0x000001FDB8920C00>'

__spec__ = None # (!) real value is "ModuleSpec(name='pyexpat', loader=<_frozen_importlib_external.ExtensionFileLoader object at 0x000001FDB8920C00>, origin='C:\\\\Users\\\\rmdri\\\\AppData\\\\Local\\\\Programs\\\\Python\\\\Python313\\\\DLLs\\\\pyexpat.pyd')"

