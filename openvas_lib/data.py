#!/usr/bin/python
# -*- coding: utf-8 -*-

"""OpenVas Data Structures."""

__license__ = """
OpenVAS connector for OMP protocol.

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
"""

import re

from collections import OrderedDict


# ------------------------------------------------------------------------------
class _Common(object):
    risk_levels = ("Critical", "High", "Medium", "Low", "None", "None", "Log", "Debug")


# ------------------------------------------------------------------------------
class OpenVASPort(object):
    """
    Port definition.
    """

    #----------------------------------------------------------------------
    def __init__(self, port_name, number, proto):
        """
        :param port_name: service name asociated (/etc/services). i.e: http
        :type port_name: str

        :param number: port number
        :type number: int

        :param proto: network protocol: tcp, udp, icmp..
        :type proto: str
        """
        if not isinstance(port_name, basestring):
            raise TypeError("Expected string, got %r instead" % type(port_name))

        if number:
            if isinstance(number, int):
                if not (0 < number < 65535):
                    raise ValueError("port must be between ranges: [0-65535], got %s instead" % number)
            else:
                raise TypeError("Expected int, got %r instead" % type(number))

        if not isinstance(proto, basestring):
            raise TypeError("Expected string, got %r instead" % type(proto))

        self.__port_name = port_name.strip()
        self.__number = number
        self.__proto = proto.strip()

    #----------------------------------------------------------------------
    @property
    def proto(self):
        """
        :return: network protocol: tcp, udp, icmp...
        :rtype: str
        """
        return self.__proto

    #----------------------------------------------------------------------
    @property
    def number(self):
        """
        :return: port number. None if not available.
        :rtype: float
        """
        return self.__number

    #----------------------------------------------------------------------
    @property
    def port_name(self):
        """
        :return: service name asociated (/etc/services). i.e: http
        :rtype: str
        """
        return self.__port_name

    #----------------------------------------------------------------------
    def __str__(self):
        return "%s (%s/%s)" % (self.port_name, self.number, self.proto)


#----------------------------------------------------------------------
class OpenVASNVT(_Common):
    """
    OpenVas NVT structure.
    """

    #----------------------------------------------------------------------
    def __init__(self):
        self.oid = None
        self.name = ""
        self.cvss_base = 0.0
        self.cvss_base_vector = None
        self.risk_factor = "None"
        self.category = "Unknown"
        self.summary = ""
        self.description = ""
        self.family = "Unknown"

        self.cves = []
        self.bids = []
        self.bugtraqs = []
        self.xrefs = []
        self.fingerprints = ""
        self.tags = []
        
        super(OpenVASNVT, self).__init__()

#------------------------------------------------------------------------------
class OpenVASOverride(_Common):
    """
    Override object of OpenVas results.
    """

    #----------------------------------------------------------------------
    def __init__(self):
        self.__nvt_oid = None
        self.__nvt_name = ""
        self.__text = ""
        self.__text_is_excerpt = False
        self.__threat = "None"
        self.__new_threat = "None"
        self.__orphan = False
        
        super(OpenVASOverride, self).__init__()

    #----------------------------------------------------------------------
    @property
    def oid(self):
        """
        :return:
        :rtype: str
        """
        return self.__nvt_oid

    #----------------------------------------------------------------------
    @oid.setter
    def oid(self, val):
        """
        :type val: basestring
        """
        if not isinstance(val, basestring):
            raise TypeError("Expected string, got %r instead" % type(val))

        self.__nvt_oid = val

    #----------------------------------------------------------------------
    @property
    def name(self):
        """
        :return: The name of the NVT
        :rtype: str
        """
        return self.__nvt_name

    #----------------------------------------------------------------------
    @name.setter
    def name(self, val):
        """
        :type val: basestring
        """
        if not isinstance(val, basestring):
            raise TypeError("Expected string, got %r instead" % type(val))

        self.__nvt_name = val

    #----------------------------------------------------------------------
    @property
    def text(self):
        """
        :return:
        :rtype: str
        """
        return self.__text

    #----------------------------------------------------------------------
    @text.setter
    def text(self, val):
        """
        :type val: basestring
        """
        if not isinstance(val, basestring):
            raise TypeError("Expected string, got %r instead" % type(val))

        self.__text = val

    #----------------------------------------------------------------------
    @property
    def text_is_excerpt(self):
        """
        :return: The text is an excerpt?
        :rtype: bool
        """
        return self.__text_is_excerpt

    #----------------------------------------------------------------------
    @text_is_excerpt.setter
    def text_is_excerpt(self, val):
        """
        :type val: bool
        """
        if not isinstance(val, bool):
            raise TypeError("Expected  bool, got %r instead" % type(val))

        self.__text_is_excerpt = val

    #----------------------------------------------------------------------
    @property
    def threat(self):
        """
        :return: one of these values: Critical|High|Medium|Low|None|Log|Debug
        :rtype: str
        """
        return self.__threat

    #----------------------------------------------------------------------
    @threat.setter
    def threat(self, val):
        """
        :type val: str - (Critical|High|Medium|Low|None|Log|Debug)
        """
        if not isinstance(val, basestring):
            raise TypeError("Expected  str - (), got %r instead" % type(val))
        if val not in self.risk_levels:
            raise ValueError("Value incorrect. Allowed values are: Critical|High|Medium|Low|None|Log|Debug, got %s instead" % val)

        self.__threat = val

    #----------------------------------------------------------------------
    @property
    def new_threat(self):
        """
        :return: one of these values: Critical|High|Medium|Low|None|Log|Debug
        :rtype: str
        """
        return self.__new_threat

    #----------------------------------------------------------------------
    @new_threat.setter
    def new_threat(self, val):
        """
        :type val: str - (Critical|High|Medium|Low|None|Log|Debug)
        """
        if not isinstance(val, basestring):
            raise TypeError("Expected  str - (), got %r instead" % type(val))
        if val not in self.risk_levels:
            raise ValueError("Value incorrect. Allowed values are: Critical|High|Medium|Low|None|Log|Debug, got %s instead" % val)

        self.__new_threat = val

    #----------------------------------------------------------------------
    @property
    def orphan(self):
        """
        :return:  indicates if the NVT is orphan
        :rtype: bool
        """
        return self.__orphan

    #----------------------------------------------------------------------
    @orphan.setter
    def orphan(self, val):
        """
        :type val: bool
        """
        if not isinstance(val, bool):
            raise TypeError("Expected bool, got %r instead" % type(val))

        self.__orphan = val


#------------------------------------------------------------------------------
class OpenVASNotes(object):
    """
    Store the notes for a results object.
    """

    #----------------------------------------------------------------------
    def __init__(self, oid, name, text, text_is_excerpt, orphan):

        if not isinstance(oid, basestring):
            raise TypeError("Expected string, got %r instead" % type(oid))
        if not isinstance(name, basestring):
            raise TypeError("Expected string, got %r instead" % type(name))
        if not isinstance(text, basestring):
            raise TypeError("Expected string, got %r instead" % type(text))
        if not isinstance(text_is_excerpt, bool):
            raise TypeError("Expected bool, got %r instead" % type(text_is_excerpt))
        if not isinstance(orphan, bool):
            raise TypeError("Expected bool, got %r instead" % type(orphan))

        self.__nvt_oid = oid
        self.__nvt_name = name
        self.__text = text
        self.__text_is_excerpt = text_is_excerpt
        self.__orphan = orphan

    #----------------------------------------------------------------------
    @property
    def oid(self):
        """
        :return:
        :rtype: basestring
        """
        return self.__nvt_oid

    #----------------------------------------------------------------------
    @property
    def name(self):
        """
        :return: The name of the note
        :rtype: basestring
        """
        return self.__nvt_name

    #----------------------------------------------------------------------
    @property
    def text(self):
        """
        :return: text related with the note
        :rtype: basestring
        """
        return self.__text

    #----------------------------------------------------------------------
    @property
    def text_is_excerpt(self):
        """
        :return: indicates if the text is an excerpt
        :rtype: bool
        """
        return self.__text_is_excerpt

    #----------------------------------------------------------------------
    @property
    def orphan(self):
        """
        :return: indicates if the note is orphan
        :rtype: bool
        """
        return self.__orphan


#------------------------------------------------------------------------------
class OpenVASResult(_Common):
    """
    Main structure to store audit results.
    """

    #----------------------------------------------------------------------
    def __init__(self):
        self.id = None
        self.subnet = None
        self.host = None
        self.port = None
        self.nvt = None
        self.threat = None
        self.description = None
        self.notes = None
        self.overrides = None

        # from nvt tags
        self.impact = ""
        self.summary = ""
        self.vulnerability_insight = ""
        self.affected_software = ""
        self.solution = ""
        
        super(OpenVASResult, self).__init__()


__all__ = [x for x in dir() if x.startswith("OpenVAS")]