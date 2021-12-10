from enum import Enum
import ipaddress
from typing import List


class ROLES(Enum):
    COSTUMER = -1
    PEER = 0
    PROVIDER = 1


class LinkedAS:
    def __init__(self, peer_as_number, our_as_number, link, role):
        self.our_as_number = our_as_number
        self.peer_as_number = peer_as_number
        self.link = link
        self.role = role

    def send_message(self, message):
        self.link.send_message(message, self.our_as_number)


def subnet_of(r1, r2):  # is r1 subnet of r2
    return ipaddress.ip_network(r1).subnet_of(ipaddress.ip_network(r2))


class AS:
    def __init__(self, as_number, connected_AS: List[LinkedAS] = None, owned_ips=None):
        # owned_ips is a list from all range ips owned by this AS , ['5.0.0.0/8','12.2.0.0/16' , ... ]
        self.as_number = as_number
        self.connected_AS = connected_AS if connected_AS else list()
        self.owned_ips = owned_ips if owned_ips else list()
        self.path_ips = {}  # {ip: [path], ...}
        self.auto_advertise = False
        pass

    def add_link(self, linked_AS: LinkedAS):
        self.connected_AS.append(linked_AS)

    def command_handler(self, command):
        command: str
        if command == "advertise all":
            self.advertise_all()
        elif command == "advertise self":
            self.advertise_self()
        elif command.startswith("get route"):
            self.get_route(command.split()[2])
        elif command.startswith("hijack"):
            self.hijack(command.split()[1])
        elif command.startswith("withdrawn"):
            self.withdrawn_ip(command.split()[1])
        elif command.startswith("link"):
            if command.split()[1] == "delete":
                self.delete_link(command.split()[2])
            else:
                self.create_link(command.split()[2])
        elif command == "auto advertise on":
            self.auto_advertise = True
        # handle commands
        # advertise all
        # advertise self
        # get route [prefix] # example: get route "12.4.0.0/16"
        # hijack [prefix]
        # withdrawn [prefix] #
        # link [delete/create] [AS_number]
        # when auto advertise is on you must advertise paths immediately after receiving it
        pass

    def withdrawn_ip(self, range_ip):
        # delete range ip and send withdrawn message to ASs
        if range_ip in self.owned_ips:
            self.owned_ips.remove(range_ip)
            for linked_as in self.connected_AS:
                self.send_message(linked_as, False, None, range_ip)
        else:
            if range_ip in self.path_ips:
                del self.path_ips[range_ip]
                for linked_as in self.connected_AS:
                    self.send_message(linked_as, False, None, range_ip)
        pass

    def withdrawn_path(self, path):
        # HINT function
        # propagate withdrawn message
        is_path = False
        if path[0] != self.as_number:
            for ip in self.path_ips.copy():
                if path[0] in self.path_ips[ip]:
                    index = self.path_ips[ip].index(path[0])
                    path_to_ip = self.path_ips[ip]
                    if (index > 0 and str(path_to_ip[index - 1]) == path[1]) or (index != len(path_to_ip)-1 and str(path_to_ip[index+1]) == path[1]):
                        del self.path_ips[ip]
                        is_path = True

        if is_path or path[0] == self.as_number:
            for linked_as in self.connected_AS:
                self.send_message(linked_as, False, path, None)

        if not is_path and path[0] != self.as_number:
            for ip in self.path_ips.copy():
                if path[1] == str(self.path_ips[ip][0]):
                    self.advertise_all()

    def hijack(self, hijack_range_ip):
        # advertise this range ip fraudly
        for linked_as in self.connected_AS:
            self.send_message(linked_as, True, [self.as_number], hijack_range_ip)
        pass

    def advertise_self(self):
        # advertise your ips
        for linked_as in self.connected_AS:
            for my_ip in self.owned_ips:
                self.send_message(linked_as, True, [self.as_number], my_ip)
        pass

    def advertise_all(self):
        # advertise all paths you know (include yourself ips)
        for linked_as in self.connected_AS:
            for ip in self.path_ips.copy():
                path = self.path_ips[ip].copy()
                path.append(self.as_number)
                if path[0] == linked_as.peer_as_number:
                    continue
                if self.get_role(path[-2]) == ROLES.COSTUMER or linked_as.role == ROLES.COSTUMER:
                    self.send_message(linked_as, True, path, ip)
        # self.advertise_self()
        pass

    def receive_message(self, message, sender_as_number):
        # use for receiving a message from a link.
        path = message["path"]
        range_ip = message["range_ip"]
        if message["is_advertise"]:
            if self.as_number not in path:
                # hijack detection
                if range_ip in self.path_ips:
                    if self.path_ips[range_ip][0] != path[0]:
                        self.print(range_ip + " hijacked.")
                        return
                if range_ip not in self.path_ips:
                    self.path_ips[range_ip] = path
                    if self.auto_advertise:
                        self.advertise_all()
                elif self.path_ips[range_ip] != path:
                    our_path_role = self.get_role(path[-1]).value
                    new_path_role = self.get_role(sender_as_number).value
                    # Role priority
                    if new_path_role > our_path_role:
                        self.path_ips[range_ip] = path
                        if self.auto_advertise:
                            self.advertise_all()
                    elif new_path_role == our_path_role:
                        # length priority
                        if len(path) < len(self.path_ips[range_ip]):
                            self.path_ips[range_ip] = path
                            if self.auto_advertise:
                                self.advertise_all()
                        elif len(path) == len(self.path_ips[range_ip]):
                            # first interface priority
                            if path[-1] < self.path_ips[range_ip][-1]:
                                self.path_ips[range_ip] = path
                                if self.auto_advertise:
                                    self.advertise_all()

        else:
            if path is None:
                self.withdrawn_ip(range_ip)
            elif range_ip is None:
                self.withdrawn_path(path)
        return

    def get_route(self, range_ip):
        # print reachable path to this range ip (use bgp algorithm)
        # print ' None + range_ip 'if it doesn't exist
        exist = False
        for ip in self.path_ips.keys():
            if not subnet_of(range_ip, ip):
                continue
            else:
                exist = True
                break
        if not exist:
            self.print("None " + range_ip)
            return

        path_to_ip = self.path_ips[ip].copy()
        path_to_ip.append(self.as_number)
        self.print(str(path_to_ip) + " " + range_ip)
        pass

    def delete_link(self, as_number):
        # handle deletion of a link
        for linked_as in self.connected_AS:
            if str(linked_as.peer_as_number) == as_number:
                self.connected_AS.remove(linked_as)
                for ip in self.path_ips.copy():
                    if as_number == str(self.path_ips[ip][-1]):
                        del self.path_ips[ip]
                self.withdrawn_path([self.as_number, as_number])
                break

    def create_link(self, as_number):
        # handle creation of a link
        # this link has already been added to your  self.connected_AS
        for linked_as in self.connected_AS:
            if linked_as.peer_as_number == as_number:
                for ip in self.path_ips.copy():
                    path = self.path_ips[ip].copy()
                    path.append(self.as_number)
                    if path[0] == linked_as.peer_as_number:
                        continue
                    if self.get_role(path[-2]) == ROLES.COSTUMER or linked_as.role == ROLES.COSTUMER:
                        self.send_message(linked_as, True, path, ip)
        self.advertise_self()
        pass

    @staticmethod
    def send_message(link, is_advertise, path, range_ip):
        link.send_message({
            "is_advertise": is_advertise,
            "path": path,
            "range_ip": range_ip
        })

    def get_role(self, as_number):
        return self.get_link(as_number).role

    def get_link(self, as_number):
        return next(filter(lambda link_as: link_as.peer_as_number == as_number, self.connected_AS))

    def print(self, *message):
        print("AS " + str(self.as_number) + ":", *message)


# This class handles communication between 2 ASes.
class Link:
    def __init__(self, first_as: AS, second_as: AS):
        self.first_as = first_as
        self.second_as = second_as

    def send_message(self, message, sender_as_id):
        if sender_as_id == self.first_as.as_number:
            self.second_as.receive_message(message, sender_as_id)
        elif sender_as_id == self.second_as.as_number:
            self.first_as.receive_message(message, sender_as_id)
        else:
            raise ValueError("Invalid target-AS.")

