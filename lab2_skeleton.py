# Don't forget to change this file's name before submission.
import sys
import os
import enum
import re
import socket
from datetime import datetime
import threading

UNSUPPORTED_METHODS = ["head", "put", "delete", "post"]
cache = {}


class HttpRequestInfo(object):
    """
    Represents a HTTP request information

    Since you'll need to standardize all requests you get
    as specified by the document, after you parse the
    request from the TCP packet put the information you
    get in this object.

    To send the request to the remote server, call to_http_string
    on this object, convert that string to bytes then send it in
    the socket.

    client_address_info: address of the client;
    the client of the proxy, which sent the HTTP request.

    requested_host: the requested website, the remote website
    we want to visit.

    requested_port: port of the webserver we want to visit.

    requested_path: path of the requested resource, without
    including the website name.

    NOTE: you need to implement to_http_string() for this class.
    """

    def __init__(self, client_info, method: str, requested_host: str,
                 requested_port: int,
                 requested_path: str,
                 headers: list):
        self.method = method
        self.client_address_info = client_info
        self.requested_host = requested_host
        self.requested_port = requested_port
        self.requested_path = requested_path
        # Headers will be represented as a list of lists
        # for example ["Host", "www.google.com"]
        # if you get a header as:
        # "Host: www.google.com:80"
        # convert it to ["Host", "www.google.com"] note that the
        # port is removed (because it goes into the request_port variable)
        self.headers = headers

    def to_http_string(self):
        """
        Convert the HTTP request/response
        to a valid HTTP string.
        As the protocol specifies:

        [request_line]\r\n
        [header]\r\n
        [headers..]\r\n
        \r\n

        (just join the already existing fields by \r\n)

        You still need to convert this string
        to byte array before sending it to the socket,
        keeping it as a string in this stage is to ease
        debugging and testing.
        """

        http_string = self.method + " "
        http_string += self.requested_path + " "
        http_string += "HTTP/1.0\r\n"
        formatted_headers = self.convert_headers_to_string()
        for header in formatted_headers:
            http_string += header
        http_string += "\r\n"
        return http_string

    def convert_headers_to_string(self):
        formatted_headers = []
        for header in self.headers:
            header_string = ""
            header_string += header[0] + ": "
            header_string += header[1] + "\r\n"
            formatted_headers.append(header_string)
        return formatted_headers

    def to_byte_array(self, http_string):
        """
        Converts an HTTP string to a byte array.
        """
        return bytes(http_string, "UTF-8")

    def display(self):
        print(f"Client:", self.client_address_info)
        print(f"Method:", self.method)
        print(f"Host:", self.requested_host)
        print(f"Port:", self.requested_port)
        stringified = [": ".join([k, v]) for (k, v) in self.headers]
        print("Headers:\n", "\n".join(stringified))


class HttpErrorResponse(object):
    """
    Represents a proxy-error-response.
    """

    def __init__(self, code, message):
        self.code = code
        self.message = message

    def to_http_string(self):
        """ Same as above """
        http_string = "HTTP/1.0 "
        http_string += str(self.code) + " "
        http_string += self.message + "\r\n"
        date_time = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        http_string += "Date: " + date_time + "\r\n"
        http_string += "Connection: close\r\n"
        return http_string

    def to_byte_array(self, http_string):
        """
        Converts an HTTP string to a byte array.
        """
        return bytes(http_string, "UTF-8")

    def display(self):
        print(self.to_http_string())


class HttpRequestState(enum.Enum):
    """
    The values here have nothing to do with
    response values i.e. 400, 502, ..etc.

    Leave this as is, feel free to add yours.
    """
    INVALID_INPUT = 0
    NOT_SUPPORTED = 1
    GOOD = 2
    PLACEHOLDER = -1


def entry_point(proxy_port_number):
    """
    Entry point, start your code here.

    Please don't delete this function,
    but feel free to modify the code
    inside it.
    """

    setup_sockets(proxy_port_number)
    return None


def setup_sockets(proxy_port_number):
    """
    Socket logic MUST NOT be written in the any
    class. Classes know nothing about the sockets.

    But feel free to add your own classes/functions.

    Feel free to delete this function.
    """
    print("Starting HTTP proxy on port:", proxy_port_number)
    # Create a TCP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Define the address
    server_address = ("127.0.0.1", int(proxy_port_number))
    # Bind the socket to the address and the port number
    server_socket.bind(server_address)
    server_socket.setsockopt(
        socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)    # Re-use the socket

    # Listen for clients
    server_socket.listen(11)
    while True:
        # Establish a connection
        client_socket, address = server_socket.accept()
        #accept_clients(client_socket, address)
        thread = threading.Thread(target=accept_clients, args=(client_socket, address, ))
        thread.start()
    server_socket.close()

    # when calling socket.listen() pass a number
    # that's larger than 10 to avoid rejecting
    # connections automatically.
    return None


def accept_clients(client_socket, address):
    request = get_client_request(client_socket)
    has_error = False
    request_info = http_request_pipeline(address, request)
    print(request_info.to_http_string())
    has_error = server_response = send_client_request_get_server_response(
        request_info, client_socket, has_error)
    if has_error == True:
        return
    send_server_response(server_response, client_socket)


def get_client_request(client_socket):
    full_request = b""
    while full_request[-4:].decode("utf-8", errors="ignore") != "\r\n\r\n":
        request = client_socket.recvfrom(128)
        full_request += request[0]
    return full_request.decode("utf-8", errors="ignore")


def send_client_request_get_server_response(request_info, client_socket, has_error):
    if request_info.to_http_string() in cache:
        return cache[request_info.to_http_string()]
    if type(request_info) == HttpErrorResponse:
        has_error = True
        client_socket.send(request_info.to_byte_array(
            request_info.to_http_string()))
        client_socket.close()
        return has_error
    else:
        web_server = (request_info.requested_host,
                      int(request_info.requested_port))
        new_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        new_socket.connect(web_server)
        new_socket.send(request_info.to_byte_array(
            request_info.to_http_string()))
        full_server_response = b""
        while True:
            response = new_socket.recvfrom(1024)
            if len(response[0]) <= 0:
                break
            full_server_response += response[0]
        new_socket.close()
        cache[request_info.to_http_string()] = full_server_response.decode(
            "utf-8", errors="ignore")
        return full_server_response.decode("utf-8", errors="ignore")


def send_server_response(server_response, client_socket):
    client_socket.send(server_response.encode("utf-8"))
    client_socket.close()


def http_request_pipeline(source_addr, http_raw_data):
    """
    HTTP request processing pipeline.

    - Validates the given HTTP request and returns
      an error if an invalid request was given.
    - Parses it
    - Returns a sanitized HttpRequestInfo

    returns:
     HttpRequestInfo if the request was parsed correctly.
     HttpErrorResponse if the request was invalid.

    Please don't remove this function, but feel
    free to change its content
    """
    # Parse HTTP request
    validity = check_http_request_validity(http_raw_data)
    # Return error if needed, then:
    if validity != HttpRequestState.GOOD:
        if validity == HttpRequestState.NOT_SUPPORTED:
            error_response = HttpErrorResponse(501, "Not Implemented")
            return error_response
        if validity == HttpRequestState.INVALID_INPUT:
            error_response = HttpErrorResponse(400, "Bad Request")
            return error_response

    # Validate, sanitize, return Http object.
    request_info = parse_http_request(source_addr, http_raw_data)
    sanitize_http_request(request_info)
    return request_info


def parse_http_request(source_addr, http_raw_data):
    """
    This function parses a "valid" HTTP request into an HttpRequestInfo
    object.
    client_info, method: str, requested_host: str,
    requested_port: int, requested_path: str,
    headers: list
    """

    client_info = source_addr
    request, headers = extract_request_and_headers(http_raw_data)
    correct_headers_format = get_correct_headers_format(headers)
    method = extract_method(request)
    host = extract_host(request[1], headers)
    port = extract_port(request[1], headers)
    path = extract_path(request[1])

    ret = HttpRequestInfo(client_info, method, host, port,
                          path, correct_headers_format)
    return ret


def get_correct_headers_format(headers):
    correct_headers_format = []
    for header in headers:
        header = header.split(" ")
        header[0] = header[0].replace(":", "")
        correct_headers_format.append(header)
    return correct_headers_format


def extract_method(request):
    return request[0]


def extract_host(url, headers):
    url_match = re.match(r"/[a-zA-Z]*", url)
    if url_match:  # Search for the host in the header
        host_match = re.findall(r"\: [\S]+", headers[0])
        if host_match:
            port_match = re.findall(r"(:[0-9]+)$", headers[0])
            port_index = len(host_match[0])
            if port_match:
                port_index = host_match[0].index(port_match[0])
            host = host_match[0][2: port_index]
            if host.startswith("http://"):
                host = host[7:]
    else:  # Search for the host in the url
        if url.startswith("http://"):
            url = url[7:]
        port_path_match = re.findall(r":[0-9]+/[a-zA-Z]*$", url)
        index = len(url) - 1
        if port_path_match:
            index = url.index(port_path_match[0])
            host = url[0: index]
        else:
            port_match = re.findall(r":[0-9]+$", url)
            if port_match:
                index = url.index(port_match[0])
                host = url[0: index]
            else:
                path_match = re.findall(r"/[a-zA-Z]*$", url)
                if path_match:
                    index = url.index(path_match[0])
                    host = url[0: index]
                else:
                    host = url
    return host


def extract_port(url, headers):
    default_port = 80
    url_match = re.match(r"/[a-zA-Z]*", url)
    if url_match:
        # Search for the port in the first header (HOST)
        port_match = re.findall(r"(:[0-9]+)$", headers[0])
        if port_match:  # If exists set the default port to this number
            default_port = port_match[0][1:]
    else:
        # Search for the port in the url
        port_match = re.findall(r":[0-9]+$", url)
        if port_match:  # If exists set the default port to this number
            default_port = port_match[0][1:]
    return default_port


def extract_path(url):
    default_path = "/"
    path_match = re.findall(r"\/[a-zA-Z]*$", url)
    if path_match:
        default_path = path_match[0]
    return default_path


def check_http_request_validity(http_raw_data) -> HttpRequestState:
    """
    Checks if an HTTP request is valid

    returns:
    One of values in HttpRequestState
    """
    if len(http_raw_data) == 0:
        return HttpRequestState.INVALID_INPUT

    request, headers = extract_request_and_headers(http_raw_data)

    http_request_state = validate_headers(headers)
    if http_request_state != HttpRequestState.GOOD:
        return http_request_state

    http_request_state = validate_request(request, headers)
    if http_request_state != HttpRequestState.GOOD:
        return http_request_state

    return HttpRequestState.GOOD


def extract_request_and_headers(http_raw_data):
    # split on new line to get the lines
    lines = http_raw_data.split("\r\n")
    while "" in lines:
        lines.remove("")
    request = lines[0].split(" ")
    headers = lines[1:]
    return request, headers


def validate_request(request, headers):

    if len(request) != 3:
        return HttpRequestState.INVALID_INPUT

    url = request[1]
    http_request_state = validate_url(url, headers)
    if http_request_state != HttpRequestState.GOOD:
        return http_request_state

    version = request[2]
    http_request_state = validate_version(version)
    if http_request_state != HttpRequestState.GOOD:
        return http_request_state

    method = request[0]
    http_request_state = validate_method(method)
    if http_request_state != HttpRequestState.GOOD:
        return http_request_state

    return HttpRequestState.GOOD


def validate_url(url, headers):
    url_match = re.match(r"/[a-zA-Z]*", url)
    if url_match == None:
        url_match = re.match(
            r"(http:\/\/)?([0-9a-zA-Z]+?\.)+[0-9a-zA-Z]+(\:[0-9]*)?(\/(([-_0-9a-zA-Z])*)?)?", url)
        if url_match == None:
            return HttpRequestState.INVALID_INPUT    # URL incorrect
    else:  # The url is a relative path and there must be a header
        if len(headers) == 0:
            return HttpRequestState.INVALID_INPUT
        elif not headers[0].startswith("Host:"):
            return HttpRequestState.INVALID_INPUT
    return HttpRequestState.GOOD


def validate_version(version):
    version_match = re.match(r"(HTTP/\d.\d)", version)

    if version_match == None:
        return HttpRequestState.INVALID_INPUT    # Version is missing / incorrect

    return HttpRequestState.GOOD


def validate_method(method):
    if method.lower() != "GET".lower():
        if method.lower() in UNSUPPORTED_METHODS:   # Method is not GET and is UNSUPPORTED
            return HttpRequestState.NOT_SUPPORTED
        return HttpRequestState.INVALID_INPUT   # Method is not GET
    return HttpRequestState.GOOD


def validate_headers(headers):
    for header in headers:
        http_request_state = validate_header(header)
        if http_request_state != HttpRequestState.GOOD:
            return http_request_state
    return HttpRequestState.GOOD


def validate_header(header):
    header_match = re.match(r"([a-zA-Z]+): ([\s\S]+)", header)
    if header_match == None:
        return HttpRequestState.INVALID_INPUT    # URL incorrect
    return HttpRequestState.GOOD


def sanitize_http_request(request_info: HttpRequestInfo):
    """
    Puts an HTTP request on the sanitized (standard) form
    by modifying the input request_info object.

    for example, expand a full URL to relative path + Host header.

    returns:
    nothing, but modifies the input object
    """
    # If there's no headers create the host header
    if len(request_info.headers) == 0:
        header = []
        header.append("Host")
        header.append(request_info.requested_host)
        request_info.headers.append(header)
    # If the first header is not the host, create it
    elif request_info.headers[0][0] != "Host":
        header = []
        header.append("Host")
        header.append(request_info.requested_host)
        request_info.headers.insert(0, header)

    # Check if the host has a port and remove it
    port_match = re.findall(r":[0-9]+$", request_info.headers[0][1])
    if port_match:
        index = request_info.headers[0][1].index(port_match[0])
        request_info.headers[0][1] = request_info.headers[0][1][0: index]
    # Check if the host starts with http:// and remove it
    if request_info.headers[0][1].startswith("http://"):
        request_info.headers[0][1] = request_info.headers[0][1][7:]

    pass


#######################################
# Leave the code below as is.
#######################################


def get_arg(param_index, default=None):
    """
        Gets a command line argument by index (note: index starts from 1)
        If the argument is not supplies, it tries to use a default value.

        If a default value isn't supplied, an error message is printed
        and terminates the program.
    """
    try:
        return sys.argv[param_index]
    except IndexError as e:
        if default:
            return default
        else:
            print(e)
            print(
                f"[FATAL] The comand-line argument #[{param_index}] is missing")
            exit(-1)    # Program execution failed.


def check_file_name():
    """
    Checks if this file has a valid name for *submission*

    leave this function and as and don't use it. it's just
    to notify you if you're submitting a file with a correct
    name.
    """
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_){,2}lab2\.py", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    else:
        print(f"[LOG] File name is correct.")


def main():
    """
    Please leave the code in this function as is.

    To add code that uses sockets, feel free to add functions
    above main and outside the classes.
    """
    print("\n\n")
    print("*" * 50)
    print(f"[LOG] Printing command line arguments [{', '.join(sys.argv)}]")
    check_file_name()
    print("*" * 50)

    # This argument is optional, defaults to 18888
    proxy_port_number = get_arg(1, 18888)
    entry_point(proxy_port_number)


if __name__ == "__main__":
    main()
