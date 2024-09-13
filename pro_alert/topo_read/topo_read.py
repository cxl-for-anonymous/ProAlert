import json
import threading
from py2neo import Graph,Node,Relationship
from py2neo.matching import *

import pandas as pd


class graph_construction:
    def __init__(self, address, database, password):
        self.address = address
        self.database = database
        self.password = password
        self.graph = Graph(self.address, auth=(self.database, self.password))

    def insert_nodes(self, node_type, nodes):
        cnt = 0
        for node in nodes:
            cnt += 1
            cql = "MERGE (:" + node_type + "{"
            for key in node.attributes_names:
                value = node.attributes_values[key]
                cql = cql + key + ":\'" + str(value) + "\',"
            cql = cql[:-1] + "})"
            # print(cql)
            print(node_type, cnt, len(nodes))
            self.graph.run(cql)

    def insert_relations(self, from_node_type, to_node_type, relation_type, relations):
        cnt = 0
        for from_node, to_node in relations:
            cnt += 1
            cql1 = "MATCH (from:" + from_node_type + " {"
            cql2 = "}), (to:" + to_node_type + " {"
            cql3 = "}) MERGE (from)-[r:" + relation_type + " { "
            for key in from_node.key_attributes:
                value = from_node.attributes_values[key]
                cql1 = cql1 + key + ":\'" + str(value) + "\',"
            for key in to_node.key_attributes:
                value = to_node.attributes_values[key]
                cql2 = cql2 + key + ":\'" + str(value) + "\',"
            cql = cql1[:-1] + cql2[:-1] + cql3[:-1] + "}]->(to)"
            # print(cql)
            self.graph.run(cql)
            print(from_node_type, to_node_type, relation_type, cnt, len(relations))

class graph_query:
    def __init__(self, address, database, password):
        self.address = address
        self.database = database
        self.password = password
        self.graph = Graph(self.address, auth=(self.database, self.password))
        self.node_matcher = NodeMatcher(self.graph)
        self.relation_matcher = RelationshipMatcher(self.graph)

    def query_nodes(self, addr_ip, physic_ip, cloud_id=''):
        node1 = self.node_matcher.match('IP', ip = addr_ip, is_hardware_ip='True').first()
        node2 = self.node_matcher.match('IP', ip = addr_ip, is_under_cloud_ip='True').first()
        node3 = self.node_matcher.match('IP', ip = physic_ip, cloud_id = str(cloud_id), is_under_cloud_ip='False', is_hardware_ip='False').first()

        target_nodes = set()
        for node in [node1,node2,node3]:
            if node is not None:
                relations = list(self.relation_matcher.match((node,None),r_type='point_to'))
                for relation in relations:
                    target_node_label = list(relation.end_node._labels)[0]
                    target_node_entity_id = relation.end_node.identity
                    target_nodes.add((target_node_entity_id, target_node_label))
                # print(target_nodes)
        return target_nodes


    def query_k_sons(self, node1_identity,num_hops):
        query = """
        MATCH (n)-[*..""" + \
        str(num_hops) +\
        """]->(reachableNode)
        WHERE id(n)=""" +\
        str(node1_identity) +\
        """
        RETURN DISTINCT reachableNode
        """
        sons = set()
        # 执行查询并获取结果
        results = self.graph.run(query)
        # 处理结果
        for record in results:
            sons.add((record[0].identity, list(record[0]._labels)[0]))
        return sons


    def query_k_fathers(self, node1_identity,num_hops):
        query = """
        MATCH (n)<-[*..""" +\
        str(num_hops) +\
        """]-(reachableNode)
        WHERE not (reachableNode:IP)
        and id(n)=""" +\
        str(node1_identity) +\
        """
        RETURN DISTINCT reachableNode
        """
        fathers = set()
        # 执行查询并获取结果
        results = self.graph.run(query)
        # 处理结果
        for record in results:
            fathers.add((record[0].identity, list(record[0]._labels)[0]))
        return fathers

    def query_k_neighbors(self, node1_identity,num_hops):
        query = """
        MATCH (n)-[*..""" +\
        str(num_hops) +\
        """]-(reachableNode)
        WHERE not (reachableNode:IP)
        and id(n)=""" +\
        str(node1_identity) +\
        """
        RETURN DISTINCT reachableNode
        """
        fathers = set()
        # 执行查询并获取结果
        results = self.graph.run(query)
        # 处理结果
        for record in results:
            fathers.add((record[0].identity, list(record[0]._labels)[0]))
        return fathers

    def query_k_hops(self, node1_identity, num_hops, edge_nodes, node_labels, k_nodes, node_edges, direction=0,
                     lock=None, limit_path=True):
        if direction > 0:
            query = """
                    MATCH p=shortestpath((n)-[*..""" + \
                    str(num_hops) + \
                    """]->(reachableNode))"""
        elif direction < 0:
            query = """
                    MATCH p=shortestpath((n)<-[*..""" + \
                    str(num_hops) + \
                    """]-(reachableNode))"""
        else:
            query = """
                    MATCH p=shortestpath((n)-[*..""" + \
                    str(num_hops) + \
                    """]-(reachableNode))"""
        query += \
        """
        WHERE not (reachableNode:IP)
        and id(n)=""" +\
        str(node1_identity) +\
        """
        and id(n)<>id(reachableNode)
        RETURN DISTINCT reachableNode, p
        """
        #and NONE(m IN nodes(p)[1..-1] WHERE 'Application' IN labels(m) or 'Storage'  IN labels(m) or 'VirtualResourceLayer' IN labels(m))
        # 执行查询并获取结果
        results = self.graph.run(query)
        not_valid = set()
        # graph.run的结果是一个迭代器，一次迭代过后就无法再迭代了，所以需要记录下
        tmp_results = []
        for i, record in enumerate(results):
            tmp_results.append(record)
            if limit_path:
                visited = set()
                for relation in record[1].relationships:
                    label1 = list(relation.start_node._labels)[0]
                    label2 = list(relation.end_node._labels)[0]
                    for label in [label1, label2]:
                        if label in ['Application', 'VirtualResourceLayer', 'Storage']:
                            # print(i, visited, node1_identity, label1, label2)
                            if label in visited:
                                not_valid.add(i)
                                break
                            visited.add(label)
        results = tmp_results
        if lock is not None:
            lock.acquire()
        k_nodes.add(node1_identity)
        node_edges[node1_identity] = []
        for i, record in enumerate(results):
            if i in not_valid:
                continue
            for relation in record[1].relationships:
                label1 = list(relation.start_node._labels)[0]
                label2 = list(relation.end_node._labels)[0]
                if label1 == 'Application':
                    label1 = relation.start_node['应用名称']
                node_labels[relation.start_node.identity] = label1
                if label2 == 'Application':
                    label2 = relation.start_node['应用名称']
                node_labels[relation.end_node.identity] = label2
                k_nodes.add(relation.start_node.identity)
                k_nodes.add(relation.end_node.identity)
                if record[0].identity not in node_edges:
                    node_edges[record[0].identity] = []
                node_edges[record[0].identity].append(relation.identity)
                edge_nodes[relation.identity] = (relation.start_node.identity, relation.end_node.identity)
        if lock is not None:
            lock.release()

    def dfs_naive(self, start, depth, num_hops, visited, edge_nodes, node_labels, k_nodes, node_edges, path_edges):
        if depth > num_hops:
            return
        ret1 = self.relation_matcher.match([start, None], r_type=None)
        ret2 = self.relation_matcher.match([None, start], r_type=None)
        for ret in [ret1,ret2]:
            for relation in ret:
                nxt_node = relation.start_node
                if nxt_node == start:
                    nxt_node = relation.end_node
                nxt_node_label = list(nxt_node._labels)[0]
                if nxt_node_label == 'IP' or nxt_node_label == 'ip' or nxt_node_label == 'Ip':
                    continue
                if relation.identity in visited:
                    continue
                # print(start.identity, nxt_node.identity)
                visited.add(relation.identity)
                k_nodes.add(nxt_node.identity)
                edge_nodes[relation.identity] = (relation.start_node.identity, relation.end_node.identity)
                node_labels[relation.start_node.identity] = list(relation.start_node._labels)[0]
                node_labels[relation.end_node.identity] = list(relation.end_node._labels)[0]
                path_edges.append(relation.identity)
                node_edges[nxt_node.identity] = [x for x in path_edges]
                if nxt_node_label == 'Application':
                    nxt_node_label = nxt_node['应用名称']
                    if nxt_node == relation.start_node:
                        node_labels[relation.start_node.identity] = nxt_node_label
                    else:
                        node_labels[relation.end_node.identity] = nxt_node_label
                    # path_edges.pop()
                    # continue
                self.dfs_naive(nxt_node, depth + 1, num_hops, visited, edge_nodes, node_labels, k_nodes, node_edges, path_edges)
                path_edges.pop()


    def dfs(self, start, depth, num_hops, visited, edge_nodes, node_labels, k_nodes, node_edges, path_edges, direction=0):
        if depth > num_hops:
            return
        rets = []
        if direction <= 0:
            ret1 = self.relation_matcher.match([start, None], r_type=None)
            rets.append(ret1)
        if direction >= 0:
            ret2 = self.relation_matcher.match([None, start], r_type=None)
            rets.append(ret2)
        for ret in rets:
            for relation in ret:
                nxt_node = relation.start_node
                if nxt_node == start:
                    nxt_node = relation.end_node
                nxt_node_label = list(nxt_node._labels)[0]
                if nxt_node_label == 'IP' or nxt_node_label == 'ip' or nxt_node_label == 'Ip':
                    continue
                if relation.identity in visited:
                    continue
                visited.add(relation.identity)
                k_nodes.add(nxt_node.identity)
                edge_nodes[relation.identity] = (relation.start_node.identity, relation.end_node.identity)
                node_labels[relation.start_node.identity] = list(relation.start_node._labels)[0]
                node_labels[relation.end_node.identity] = list(relation.end_node._labels)[0]
                path_edges.append(relation.identity)
                node_edges[nxt_node.identity] = [x for x in path_edges]
                if nxt_node_label == 'Application':
                    nxt_node_label = nxt_node['应用名称']
                    if nxt_node == relation.start_node:
                        node_labels[relation.start_node.identity] = nxt_node_label
                    else:
                        node_labels[relation.end_node.identity] = nxt_node_label
                    path_edges.pop()
                    continue
                if nxt_node_label == 'Storage':
                    path_edges.pop()
                    continue
                if nxt_node_label == 'VirtualResourceLayer':
                    path_edges.pop()
                    continue
                self.dfs(nxt_node, depth + 1, num_hops, visited, edge_nodes, node_labels, k_nodes, node_edges, path_edges)
                path_edges.pop()


    def query_k_edges_naive(self, node1_identity, num_hops):
        neighbor_edges = dict()
        neighbor_nodes = set()
        neighbor_node_paths = dict()
        node_labels = dict()
        target = self.node_matcher[int(node1_identity)]
        self.dfs_naive(target, 0, num_hops, set(), neighbor_edges, node_labels, neighbor_nodes, neighbor_node_paths, [])
        return node_labels, neighbor_edges,neighbor_nodes,neighbor_node_paths

    def query_k_edges(self, node1_identity, num_hops):
        neighbor_edges = dict()
        neighbor_nodes = set()
        neighbor_node_paths = dict()
        node_labels = dict()
        target = self.node_matcher[int(node1_identity)]
        self.dfs(target, 0, num_hops, set(), neighbor_edges, node_labels, neighbor_nodes, neighbor_node_paths, [])
        return node_labels, neighbor_edges, neighbor_nodes,neighbor_node_paths


    def query_k_edges_single_direction(self, node1_identity, num_hops):
        edge_node_pair = dict()
        node_label = dict()
        reachable_nodes = set()
        reachable_node_paths = dict()
        lock = threading.Lock()
        thread1 = threading.Thread(target=self.query_k_hops,args=(node1_identity, num_hops, edge_node_pair, node_label, reachable_nodes, reachable_node_paths, 1, lock))
        thread2 = threading.Thread(target=self.query_k_hops,args=(node1_identity, num_hops, edge_node_pair, node_label, reachable_nodes, reachable_node_paths, -1, lock))
        thread1.start()
        thread2.start()
        for thread in [thread1, thread2]:
            thread.join()
        # self.query_k_hops(node1_identity, num_hops, edge_node_pair, node_label, reachable_nodes, reachable_node_paths, direction=1)
        # self.query_k_hops(node1_identity, num_hops, edge_node_pair, node_label, reachable_nodes, reachable_node_paths, direction=-1)
        # target = self.node_matcher[int(node1_identity)]
        # self.dfs(target, 0, num_hops, set(), edge_node_pair, node_label, reachable_nodes, reachable_node_paths, [], 1)
        # self.dfs(target, 0, num_hops, set(), edge_node_pair, node_label, reachable_nodes, reachable_node_paths, [], -1)
        return edge_node_pair, node_label, reachable_nodes,reachable_node_paths


    def query_k_edges_both_direction(self, node1_identity, num_hops):
        edge_node_pair = dict()
        node_label = dict()
        reachable_nodes = set()
        reachable_node_paths = dict()
        lock = threading.Lock()
        thread1 = threading.Thread(target=self.query_k_hops,args=(node1_identity, num_hops, edge_node_pair, node_label, reachable_nodes, reachable_node_paths, 0, lock, False))
        thread1.start()
        thread1.join()
        return edge_node_pair, node_label, reachable_nodes,reachable_node_paths

    def query_k_edges_single_direction(self, node1_identity, num_hops):
        edge_node_pair = dict()
        node_label = dict()
        reachable_nodes = set()
        reachable_node_paths = dict()
        lock = threading.Lock()
        thread1 = threading.Thread(target=self.query_k_hops,args=(node1_identity, num_hops, edge_node_pair, node_label, reachable_nodes, reachable_node_paths, 1, lock))
        thread2 = threading.Thread(target=self.query_k_hops,args=(node1_identity, num_hops, edge_node_pair, node_label, reachable_nodes, reachable_node_paths, -1, lock))
        thread1.start()
        thread2.start()
        for thread in [thread1, thread2]:
            thread.join()
        # self.query_k_hops(node1_identity, num_hops, edge_node_pair, node_label, reachable_nodes, reachable_node_paths, direction=1)
        # self.query_k_hops(node1_identity, num_hops, edge_node_pair, node_label, reachable_nodes, reachable_node_paths, direction=-1)
        # target = self.node_matcher[int(node1_identity)]
        # self.dfs(target, 0, num_hops, set(), edge_node_pair, node_label, reachable_nodes, reachable_node_paths, [], 1)
        # self.dfs(target, 0, num_hops, set(), edge_node_pair, node_label, reachable_nodes, reachable_node_paths, [], -1)
        return edge_node_pair, node_label, reachable_nodes,reachable_node_paths


if __name__ == '__main__':
    # # # # # # http://10.162.206.113:7474/
    gq = graph_query('bolt://localhost:7687', 'neo4j', '123456789')
    nodes = list(gq.query_k_hops(8, 3, dict(), dict(), set(), dict()))
    for node in nodes:
        print(node)