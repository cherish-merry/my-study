from pyroute2 import IPRoute

if __name__ == '__main__':
    with IPRoute() as ipr:
        print([x.get_attr('IFLA_IFNAME') for x in ipr.get_links()])
