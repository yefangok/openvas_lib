#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
OpenVAS connector for OMP protocol.

This is a replacement of the official library OpenVAS python library,
because the official library doesn't work with OMP v4.0.
"""

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

__all__ = [x for x in dir() if x.startswith("Vulnscan") or x.startswith("report_parser")]

import os
import logging

from collections import Iterable
from six import iteritems
try:
    from xml.etree import cElementTree as etree
except ImportError:
    from xml.etree import ElementTree as etree

from openvas_lib.data import *
from openvas_lib.utils import *
from openvas_lib.common import *


#------------------------------------------------------------------------------
#
# Stand alone parser
#
#------------------------------------------------------------------------------
def report_parser_from_text(text, ignore_log_info=True):
    """
    This functions transform XML OpenVas file report to OpenVASResult object structure.

    To pass string as parameter:
    >>> xml='<report extension="xml" type="scan" id="aaaa" content_type="text/xml" format_id="a994b278-1f62-11e1-96ac-406186ea4fc5"></report>'
    >>> report_parser_from_text(f)
    [OpenVASResult]

    Language specification: http://www.openvas.org/omp-4-0.html

    :param text: xml text to parse.
    :type text: str

    :param ignore_log_info: Ignore Threats with Log and Debug info
    :type ignore_log_info: bool

    :raises: etree.ParseError, IOError, TypeError

    :return: list of OpenVASResult structures.
    :rtype: list(OpenVASResult)
    """
    if not isinstance(text, basestring):
        raise TypeError("Expected basestring, got '%s' instead" % type(text))

    try:
        import cStringIO as S
    except ImportError:
        import StringIO as S

    return report_parser(S.StringIO(text), ignore_log_info)


def report_parser(report, ignore_log_info=True):
    """
    This functions transform XML OpenVas file report to OpenVASResult object structure.

    To pass StringIO file as parameter, you must do that:
    >>> import StringIO
    >>> xml='<report extension="xml" type="scan" id="aaaa" content_type="text/xml" format_id="a994b278-1f62-11e1-96ac-406186ea4fc5"></report>'
    >>> f=StringIO.StringIO(xml)
    >>> report_parser(f)
    [OpenVASResult]

    To pass a file path:
    >>> xml_path='/home/my_user/openvas_result.xml'
    >>> report_parser(xml_path)
    [OpenVASResult]

    Language specification: http://www.openvas.org/omp-4-0.html

    :param path_or_file: path or file descriptor to xml file.
    :type path_or_file: str | file | StringIO

    :param ignore_log_info: Ignore Threats with Log and Debug info
    :type ignore_log_info: bool

    :raises: etree.ParseError, IOError, TypeError

    :return: list of OpenVASResult structures.
    :rtype: list(OpenVASResult)
    """
    if type(report).__name__ == "Element":
        xml_parsed = report
    elif type(report).__name__ == "ElementTree":
        xml_parsed = report.getroot()
    else:
        # Parse XML file
        try:
            xml_parsed = etree.parse(report)
        except etree.ParseError:
            raise etree.ParseError("Invalid XML file. Ensure file is correct and all tags are properly closed.")

    # Use this method, because API not exposes real path and if you write isisntance(xml_results, Element)
    # doesn't works
    if type(xml_parsed).__name__ == "Element":
        xml = xml_parsed
    elif type(xml_parsed).__name__ == "ElementTree":
        xml = xml_parsed.getroot()
    else:
        raise TypeError("Expected ElementTree or Element, got '%s' instead" % type(xml_parsed))

    # Regex
    m_return = []

    # All the results
    for l_results in xml.findall(".//result"):
        xml = parse_result(l_results, ignore_log_info)
        if xml:
            m_return.append(xml)

    return m_return


def parse_result(result, ignore_log_info=True):
    port_regex_specific = re.compile("([\w\d\s]*)\(([\d]+)/([\w\W\d]+)\)")
    port_regex_generic = re.compile("([\w\d\s]*)/([\w\W\d]+)")
    vulnerability_ids = ("cve", "bid", "bugtraq")

    # generate an object
    openvas_result = OpenVASResult()

    # Id
    vid = result.get("id")
    openvas_result.id = vid

    # For each child tag in a result
    for el in result.getchildren():
        tag_name = el.tag

        # simple tags we want to grab the contents of
        if tag_name in ("subnet", "host", "threat", "severity", "description"):
            setattr(openvas_result, tag_name, el.text)
        elif tag_name == "port" and isinstance(el.text, string_types):
            # Looking for port as format: https (443/tcp)
            port = port_regex_specific.search(el.text)
            if port:
                service = port.group(1)
                number = int(port.group(2))
                proto = port.group(3)
                openvas_result.port = {'service': service, 'number': number, 'protocol': proto}
            else:
                # Looking for port as format: general/tcp
                port = port_regex_generic.search(el.text)
                if port:
                    service = port.group(1)
                    proto = port.group(2)
                    openvas_result.port = {'service': service, 'number': 0, 'protocol': proto}

        # grab all the nvt tags
        elif tag_name == "nvt":

            # The NVT Object
            nvt_object = OpenVASNVT()
            nvt_object.oid = el.attrib['oid']

            # Sub nodes of NVT tag
            l_nvt_symbols = [x for x in dir(nvt_object) if not x.startswith("_")]

            for el_nvt in el.getchildren():
                nvt_tag_name = el_nvt.tag

                # For each xml tag...
                if nvt_tag_name in l_nvt_symbols:

                    # For elements with content, like: <cert>blah</cert>
                    if el_nvt.text:
                        if nvt_tag_name.lower() == 'tags':
                            kvpairs = el_nvt.text.split('|')
                            for line in kvpairs:
                                try:
                                    k, v = line.split('=', 2)
                                    if hasattr(nvt_object, k):
                                        setattr(nvt_object, k, v.strip())
                                except ValueError, e:
                                    pass
                        # for filter tags like <cve>NOCVE</cve>
                        elif el_nvt.text.startswith("NO"):
                            setattr(nvt_object, nvt_tag_name, el_nvt.text)
                        # elements with valid content
                        else:
                            if nvt_tag_name.lower() in vulnerability_ids:
                                l_nvt_text = getattr(el_nvt, "text", "")
                                setattr(nvt_object, nvt_tag_name, l_nvt_text.split(","))
                                continue
                            else:
                                l_nvt_text = getattr(el_nvt, "text", "")
                                setattr(nvt_object, nvt_tag_name, l_nvt_text)
                                continue

                    # For filter tags without content, like: <cert/>
                    else:
                        setattr(nvt_object, nvt_tag_name, "")

            # Add to the NVT Object
            openvas_result.nvt = nvt_object

        else:
            # Unrecognised tag
            logging.warning("%s tag unrecognised" % tag_name)

    # Add to the return values
    return openvas_result


#------------------------------------------------------------------------------
#
# High level exceptions
#
#------------------------------------------------------------------------------

#------------------------------------------------------------------------------
class VulnscanException(Exception):
    """Base class for OpenVAS exceptions."""


#------------------------------------------------------------------------------
class VulnscanAuthFail(VulnscanException):
    """Authentication failure."""


#------------------------------------------------------------------------------
class VulnscanServerError(VulnscanException):
    """Error message from the OpenVAS server."""


#------------------------------------------------------------------------------
class VulnscanClientError(VulnscanException):
    """Error message from the OpenVAS client."""


#------------------------------------------------------------------------------
class VulnscanProfileError(VulnscanException):
    """Profile error."""


#------------------------------------------------------------------------------
class VulnscanTargetError(VulnscanException):
    """Target related errors."""


#------------------------------------------------------------------------------
class VulnscanScanError(VulnscanException):
    """Task related errors."""


#------------------------------------------------------------------------------
class VulnscanVersionError(VulnscanException):
    """Wrong version of OpenVAS server."""


#------------------------------------------------------------------------------
class VulnscanTaskNotFinishedError(VulnscanException):
    """Wrong version of OpenVAS server."""


#------------------------------------------------------------------------------
class VulnscanAuditNotRunningError(VulnscanException):
    """Wrong version of OpenVAS server."""


#------------------------------------------------------------------------------
class VulnscanAuditNotFoundError(VulnscanException):
    """Wrong version of OpenVAS server."""


#------------------------------------------------------------------------------
#
# High level interface
#
#------------------------------------------------------------------------------
class VulnscanManager(object):
    """
    High level interface to the OpenVAS server.

    ..warning: Only compatible with OMP 4.0.
    """

    #----------------------------------------------------------------------
    #
    # Methods to manage OpenVAS
    #
    #----------------------------------------------------------------------
    def __init__(self, host, user, password, port=9390, timeout=None):
        """
        :param host: The host where the OpenVAS server is running.
        :type host: str

        :param user: Username to connect with.
        :type user: str

        :param password: Password to connect with.
        :type password: str

        :param port: Port number of the OpenVAS server.
        :type port: int

        :raises: VulnscanServerError, VulnscanAuthFail, VulnscanVersionError
        """

        if not isinstance(host, basestring):
            raise TypeError("Expected string, got %r instead" % type(host))
        if not isinstance(user, basestring):
            raise TypeError("Expected string, got %r instead" % type(user))
        if not isinstance(password, basestring):
            raise TypeError("Expected string, got %r instead" % type(password))
        if isinstance(port, int):
            if not (0 < port <= 65535):
                raise ValueError("Port number must be in range (0, 65535]")
        else:
            raise TypeError("Expected int, got %r instead" % type(port))

        m_time_out = None
        if timeout:
            if isinstance(timeout, int):
                if timeout < 1:
                    raise ValueError("Timeout value must be greater than 0.")
                else:
                    m_time_out = timeout
            else:
                raise TypeError("Expected int, got %r instead" % type(timeout))

        # Create the manager
        try:
            self.__manager = get_connector(host, user, password, port, m_time_out)
        except ServerError, e:
            raise VulnscanServerError("Error while connecting to the server: %s" % e.message)
        except AuthFailedError:
            raise VulnscanAuthFail("Error while trying to authenticate into the server.")
        except RemoteVersionError:
            raise VulnscanVersionError("Invalid OpenVAS version in remote server.")

        #
        # Flow control

        # Error counter
        self.__error_counter = 0

        # Old progress
        self.__old_progress = 0.0

        # Init various vars
        self.__function_handle = None
        self.__task_id = None
        self.__target_id = None

    #----------------------------------------------------------------------
    def create_scan(self, targets, profile='Full and fast', tcp_ports=None, udp_ports=None,
                    credentials=None, **kwargs):
        if not (isinstance(targets, basestring) or isinstance(targets, Iterable)):
            raise TypeError("Expected basestring or iterable, got %r instead" % type(targets))

        target_name = "openvas_lib_target_%s_%s" % (targets, generate_random_string(20))
        port_list_name = "openvas_lib_portlist_%s_%s" % (targets, generate_random_string(20))
        job_name = "openvas_lib_scan_%s_%s" % (targets, generate_random_string(20))

        # Get the profile ID by their name
        try:
            tmp = self.__manager.get_configs_ids(profile)
            profile_id = tmp[profile]
        except ServerError, e:
            raise VulnscanProfileError("The profile does not exits on the server. Error: %s" % e.message)
        except KeyError:
            raise VulnscanProfileError("The profile does not exits on the server.")

        # Port list
        try:
            port_list_id = self.__manager.create_port_list(port_list_name, tcp_ports=tcp_ports, udp_ports=udp_ports)
        except ServerError, e:
            raise VulnscanProfileError("The portlist you suggested was not accepted by the server or already exists. " +
                                       "Error: %s" % e.message)



        # Create the target
        try:
            target_id = self.__manager.create_target(target_name, targets, "Temporal target from OpenVAS Lib",
                                                     port_list=port_list_id)
        except ServerError, e:
            raise VulnscanTargetError("The target already exits on the server. Error: %s" % e.message)


        # Create task
        try:
            task_id = self.__manager.create_task(job_name, target_id, config=profile_id, comment="Scan by OpenVAS lib")
        except ServerError, e:
            raise VulnscanScanError("The target selected doesnn't exist in the server. Error: %s" % e.message)

        return task_id, target_id

    #----------------------------------------------------------------------
    def launch_scan(self, task_id=None, **kwargs):
        """
        Launch a new audit in OpenVAS.

        This is an example code to launch an OpenVAS scan and wait for it
        to complete::

            from threading import Semaphore
            from functools import partial

            def my_print_status(i): print str(i)

            def my_launch_scanner():

                Sem = Semaphore(0)

                # Configure
                manager = VulnscanManager("localhost", "admin", "admin)

                # Launch
                manager.launch_scan(
                    target,
                    profile = "empty",
                    callback_end = partial(lambda x: x.release(), sem),
                    callback_progress = my_print_status
                )

                # Wait
                Sem.acquire()

                # Finished scan
                print "finished!"

            # >>> my_launch_scanner() # It can take some time
            # 0
            # 10
            # 39
            # 60
            # 90
            # finished!

        :param target: Target to audit.
        :type target: str

        :param profile: Scan profile in the OpenVAS server.
        :type profile: str

        :param callback_end: If this param is set, the process will run in background
                             and call the function specified in this var when the
                             scan ends.
        :type callback_end: function

        :param callback_progress: If this param is set, it will be called every 10 seconds,
                                  with the progress percentaje as a float.
        :type callback_progress: function(float)

        :return: ID of the audit and ID of the target: (ID_scan, ID_target)
        :rtype: (str, str)
        """

        call_back_end = kwargs.get("callback_end", None)
        call_back_progress = kwargs.get("callback_progress", None)

        # Start the scan
        try:
            self.__manager.start_task(task_id)
        except ServerError, e:
            raise VulnscanScanError("Unknown error while try to start the task '%s'. Error: %s" % (task_id, e.message))

        # Callback is set?
        if call_back_end or call_back_progress:
            # schedule a function to run each 10 seconds to check the estate in the server
            self.__task_id = task_id
            self.__function_handle = self._callback(call_back_end, call_back_progress)

        return task_id

    #----------------------------------------------------------------------
    @property
    def task_id(self):
        """
        :returns: OpenVAS task ID.
        :rtype: str
        """
        return self.__task_id

    #----------------------------------------------------------------------
    @property
    def target_id(self):
        """
        :returns: OpenVAS target ID.
        :rtype: str
        """
        return self.__target_id

    #----------------------------------------------------------------------
    def delete_scan(self, task_id):
        """
        Delete specified scan ID in the OpenVAS server.

        :param task_id: Scan ID.
        :type task_id: str

        :raises: VulnscanAuditNotFoundError
        """
        try:
            self.__manager.delete_task(task_id)
        except AuditNotRunningError, e:
            raise VulnscanAuditNotFoundError(e)

    #----------------------------------------------------------------------
    def delete_target(self, target_id):
        """
        Delete specified target ID in the OpenVAS server.

        :param target_id: Target ID.
        :type target_id: str
        """
        self.__manager.delete_target(target_id)

    #----------------------------------------------------------------------
    def get_results(self, task_id):
        """
        Get the results associated to the scan ID.

        :param task_id: Scan ID.
        :type task_id: str

        :return: Scan results.
        :rtype: list(OpenVASResult)

        :raises: ServerError, TypeError
        """

        if not isinstance(task_id, basestring):
            raise TypeError("Expected string, got %r instead" % type(task_id))

        if self.__manager.is_task_running(task_id):
            raise VulnscanTaskNotFinishedError("Task is currently running. Until it not finished, you can't obtain the results.")

        try:
            m_response = self.__manager.get_results(task_id)
        except ServerError, e:
            raise VulnscanServerError("Can't get the results for the task %s. Error: %s" % (task_id, e.message))

        return report_parser(m_response)

    #----------------------------------------------------------------------
    def get_report_id(self, scan_id):

        if not isinstance(scan_id, basestring):
            raise TypeError("Expected string, got %r instead" % type(scan_id))

        return self.__manager.get_report_id(scan_id)

    #----------------------------------------------------------------------
    def get_report_html(self, report_id):

        if not isinstance(report_id, basestring):
            raise TypeError("Expected string, got %r instead" % type(report_id))

        return self.__manager.get_report_html(report_id)
        #----------------------------------------------------------------------

    #----------------------------------------------------------------------
    def get_report_xml(self, report_id):

        if not isinstance(report_id, basestring):
            raise TypeError("Expected string, got %r instead" % type(report_id))

        return self.__manager.get_report_xml(report_id)
        #----------------------------------------------------------------------

    #----------------------------------------------------------------------
    def get_report_pdf(self, report_id):

        if not isinstance(report_id, basestring):
            raise TypeError("Expected string, got %r instead" % type(report_id))

        return self.__manager.get_report_pdf(report_id)

    #----------------------------------------------------------------------
    def get_progress(self, task_id):
        """
        Get the progress of a scan.

        :param task_id: Scan ID.
        :type task_id: str

        :return: Progress percentage (between 0.0 and 100.0).
        :rtype: float
        """
        if not isinstance(task_id, basestring):
            raise TypeError("Expected string, got %r instead" % type(task_id))

        return self.__manager.get_tasks_progress(task_id)

    #----------------------------------------------------------------------
    def stop_audit(self, task_id):
        """
        Stops specified scan ID in the OpenVAS server.

        :param task_id: Scan ID.
        :type task_id: str

        :raises: AuditNotFoundError
        """
        try:
            self.__manager.stop_task(task_id)
        except AuditNotRunningError, e:
            raise VulnscanAuditNotFoundError(e)

    #----------------------------------------------------------------------
    @property
    def get_profiles(self):
        """
        :return: All available profiles.
        :rtype: {profile_name: ID}
        """
        return self.__manager.get_configs_ids()

    #----------------------------------------------------------------------
    @property
    def get_all_scans(self):
        """
        :return: All scans.
        :rtype: {scan_name: ID}
        """
        return self.__manager.get_tasks_ids()

    #----------------------------------------------------------------------
    @property
    def get_running_scans(self):
        """
        :return: All running scans.
        :rtype: {scan_name: ID}
        """
        return self.__manager.get_tasks_ids_by_status("Running")

    #----------------------------------------------------------------------
    @property
    def get_finished_scans(self):
        """
        :return: All finished scans.
        :rtype: {scan_name: ID}
        """
        return self.__manager.get_tasks_ids_by_status("Done")

    #----------------------------------------------------------------------
    @set_interval(10.0)
    def _callback(self, func_end, func_status):
        """
        This callback function is called periodically from a timer.

        :param func_end: Function called when task end.
        :type func_end: funtion pointer

        :param func_status: Function called for update task status.
        :type func_status: funtion pointer
        """
        # Check if audit was finished
        try:
            if not self.__manager.is_task_running(self.task_id):
                # Task is finished. Stop the callback interval
                self.__function_handle.set()

                # Call the callback function
                if func_end:
                    func_end()

                # Reset error counter
                self.__error_counter = 0

        except (ClientError, ServerError, Exception), e:
            self.__error_counter += 1

            # Checks for error number
            if self.__error_counter >= 5:
                # Stop the callback interval
                self.__function_handle.set()

                func_end()

        if func_status:
            try:
                t = self.get_progress(self.task_id)

                # Save old progress
                self.__old_progress = t

                func_status(1.0 if t == 0.0 else t)

            except (ClientError, ServerError, Exception), e:

                func_status(self.__old_progress)