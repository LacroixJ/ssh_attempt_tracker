#!/usr/bin/env python3



class Ip_stat():

    def __init__(self, address):
        self.fails = 0
        self.usernames = []
        self.ip = address

    #Called when invalid pass made for valid user
    def fail(self, username):
        self.fails += 1
        if username not in self.usernames:
            self.usernames.append(username)


class Auth_log_parser():


    def __init__(self):
        self.ips = {}

    def parse(self, filename):
        with open(filename) as f:
            #There is 3 cases for fails to happen
            for line in f:
                line = line.strip('\n').split()
                if 'Invalid' in line:
                    name = line[7]
                    ip = line[9]
                elif 'invalid' in line and 'for' in line:
                    name = line[10]
                    ip = line[12]
                elif 'Failed' in line:
                    name = line[8]
                    ip = line[10]
                else: continue

                if ip not in self.ips.keys():
                    self.ips[ip] = Ip_stat(ip)

                self.ips[ip].fail(name)


    def total_fails(self):
        fails = 0
        for key, ip in self.ips.items():
            fails += ip.fails
        return fails

    def total_ips(self):
        return len(self.ips)

    def max(self):
        highest = 0
        by = None
        for key, ip in self.ips.items():
            if ip.fails > highest:
                highest = ip.fails
                by = ip
        return by




    def __repr__(self):
        result = ''
        for key, ip in self.ips.items():
            result += f'ip: {key}, fails: {ip.fails}\n'
            result += 'usernames:'
            for username in ip.usernames:
                result += f' {username}, '
            result = result.strip(', ')
            result += '\n\n'

        result += f'Total fails: {self.total_fails()}\n'
        result += f'Unique IP adresses: {self.total_ips()}\n'

        highest_ip = self.max()

        result += f'Highest attempts by: {highest_ip.ip} with {highest_ip.fails} attempts.\n'


        return result





parser = Auth_log_parser()
parser.parse('auth.log')
parser.parse('auth.log.1')

print(parser)
