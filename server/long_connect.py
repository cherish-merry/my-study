import re
import socket


def service_client(new_socket, request):
    """为这个客户端返回数据"""

    #  接收浏览器发送过来的请求，即HTTP请求
    # request=new_socket.recv(1024)
    # request=request.decode("utf-8")  #  解码
    print(request)
    request_lines = request.splitlines()  # 按照行('\r', '\r\n', \n')分隔，返回一个包含各行作为元素的列表
    print(request_lines)

    #  GET /index.html HTTP/1.1
    #  [^/]表示除了/都可以
    file_name = ""
    ret = re.match(r"[^/]+(/[^ ]*)", request_lines[0])
    if ret:
        file_name = ret.group(1)
        if file_name == "/":
            file_name = "/index.html"

    #  2.返回HTTP格式的数据，给浏览器

    try:
        #  准备发送的body，打开HTML文件
        f = open("html" + file_name, 'rb')
    except:
        response = "HTTP/1.1 404 NOT FOUND\r\n"
        response += '\r\n'
        response += "----file not found----"
        new_socket.send(response.encode("utf-8"))
    else:
        html_content = f.read()
        f.close()
        response_body = html_content
        #  准备发送的header
        response_header = "HTTP/1.1 200 OK\r\n"
        response_header += "Content-Length:%d\r\n" % len(response_body)
        response_header += "\r\n"  # header与body之间必须隔一行

        response = response_header.encode("utf-8") + response_body
        #  发送response
        new_socket.send(response)

    #  长连接不需要关闭
    # new_socket.close()


def main():
    tcp_sever_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #  服务器先关闭，保证重新开启不占用端口
    tcp_sever_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp_sever_socket.bind(("", 7777))
    tcp_sever_socket.listen(65635)
    tcp_sever_socket.setblocking(False)  # 套接字设为非阻塞

    client_socket_list = list()
    while True:
        try:
            #  等待新客户端的链接
            new_socket, client_addr = tcp_sever_socket.accept()
        except Exception as ret:
            pass
        else:
            new_socket.setblocking(False)
            client_socket_list.append(new_socket)

        for client_socket in client_socket_list:
            try:
                recv_data = client_socket.recv(1024).decode("utf-8")
            except Exception as ret:
                pass
            else:
                if recv_data:
                    service_client(client_socket, recv_data)
                # else:
                #     client_socket.close()
                #     client_socket_list.remove(client_socket)

    tcp_sever_socket.close()


if __name__ == '__main__':
    main()
