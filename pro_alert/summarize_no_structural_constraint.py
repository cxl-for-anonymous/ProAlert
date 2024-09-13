import os.path

import math
import torch

from alert_denoise.alert_denoise import read_alerts
from topo_read.topo_read import graph_query
import datetime
from collections import deque
import numpy as np
from sentence_transformers import SentenceTransformer
import csv
import logging

logging.basicConfig(filename='compress_log.txt', level=logging.CRITICAL, filemode='a', force=True)


def clear_content(ret):
    ret = ret.replace('<\d>', ' ').replace('<*>', ' ').replace('\"', ' ').replace('/', ' ').replace(';', ' ').replace(
        ',', ' ').replace('：', ' ')
    ret = ret.replace(':', ' ').replace('[ ]', ' ').replace('[ _ ]', '').replace('[ __ ]', '').replace('[ - ]',
                                                                                                       '').replace(
        '[ -- ]', '')
    ret = ret.replace('[', ' ').replace(']', ' ').replace('+', '').replace('-', '').replace('_', '').replace('=', '')
    while '  ' in ret:
        ret = ret.replace('  ', ' ')
    ret = ret.strip()
    return ret


def query_and_store_k_hops(node_id, k_nodes_dict, edge_node_pair, node_label, k_paths_dict, gq, num_hops):
    if node_id not in k_nodes_dict:
        neighbor_edges, neighbor_node_labels, neighbor_nodes, neighbor_node_paths = gq.query_k_edges_both_direction(
            node_id, num_hops)
        edge_node_pair.update(neighbor_edges)
        node_label.update(neighbor_node_labels)
        k_nodes_dict[node_id] = neighbor_nodes
        k_paths_dict[node_id] = neighbor_node_paths


def query_and_store_common_paths(target_nodes, other_nodes, common_edge_dict, k_nodes_dict,
                                 edge_node_pair,
                                 node_label, k_paths_dict,
                                 gq, num_hops):
    total_nodes = str((target_nodes, other_nodes))
    if total_nodes in common_edge_dict:
        return common_edge_dict[total_nodes]
    total_nodes = str((other_nodes, target_nodes))
    if total_nodes in common_edge_dict:
        return common_edge_dict[total_nodes]
    common_paths = set()
    for node_id, node_type in target_nodes:
        query_and_store_k_hops(node_id, k_nodes_dict, edge_node_pair, node_label, k_paths_dict, gq,
                               math.ceil(num_hops / 2.0))
        for other_node_id, other_node_type in other_nodes:
            if node_id == other_node_id:
                continue
            query_and_store_k_hops(other_node_id, k_nodes_dict, edge_node_pair, node_label, k_paths_dict, gq,
                                   math.ceil(num_hops / 2.0))
            if len(k_nodes_dict[node_id] & k_nodes_dict[other_node_id]) > 0:
                tmp = k_nodes_dict[node_id] & k_nodes_dict[other_node_id]
                for common_node_id in tmp:
                    if len(k_paths_dict[node_id][common_node_id]) + len(
                            k_paths_dict[other_node_id][common_node_id]) > num_hops:
                        continue
                    path_edges = set()
                    for edge_id in k_paths_dict[node_id][common_node_id]:
                        path_edges.add(edge_node_pair[edge_id])
                    for edge_id in k_paths_dict[other_node_id][common_node_id]:
                        path_edges.add(edge_node_pair[edge_id])
                    path_edges = list(path_edges)
                    path_edges.sort()
                    common_paths.add(tuple(path_edges))
    common_edge_dict[total_nodes] = common_paths
    return common_paths


def get_closet_feature(target_template_v, features):
    closet_score = torch.max(torch.matmul(features, target_template_v.T)).item()
    return closet_score


def choose_tagged_path(target_template_v, other_template_v, label_pair_features, common_label_paths, node_label):
    max_score = -1
    max_path = None
    visited = set()
    for path_edges in common_label_paths:
        path_score = 1
        for node_id1, node_id2 in path_edges:
            label1 = node_label[node_id1]
            label2 = node_label[node_id2]
            label_pair = [label1, label2]
            label_pair.sort()
            label_pair = tuple(label_pair)
            if label_pair in visited:
                continue
            visited.add(label_pair)
            if label_pair not in label_pair_features:
                continue
            tmp_score1 = get_closet_feature(target_template_v, label_pair_features[label_pair])
            tmp_score2 = get_closet_feature(other_template_v, label_pair_features[label_pair])
            path_score = min(path_score, tmp_score1)
            path_score = min(path_score, tmp_score2)
        if path_score > max_score:
            max_score = path_score
            max_path = path_edges
    return max_score, max_path


def check_path(incident_node_degree, tmp_path, incident_id):
    if incident_id not in incident_node_degree:
        return True
    in_degree = dict()
    out_degree = dict()
    for node in incident_node_degree[incident_id]:
        in_degree[node] = incident_node_degree[incident_id][node][0]
        out_degree[node] = incident_node_degree[incident_id][node][1]
    for u, v in tmp_path:
        if u not in out_degree:
            out_degree[u] = 0
        if u not in in_degree:
            in_degree[u] = 0
        if v not in out_degree:
            out_degree[v] = 0
        if v not in in_degree:
            in_degree[v] = 0
        out_degree[u] += 1
        in_degree[v] += 1
    zero_in = 0
    zero_out = 0
    for node in in_degree:
        if in_degree[node] == 0:
            zero_in += 1
            if zero_in > 1:
                break
    for node in out_degree:
        if out_degree[node] == 0:
            zero_out += 1
            if zero_out > 1:
                break
    if zero_in == 1 or zero_out == 1:
        return True
    return False


def prepare_input_data(file_path, train_factor, template_col, template_id_col, topo_col, k_nodes_dict, edge_node_pair,
                       node_label,
                       k_paths_dict,
                       graph_query, num_hops, embed_template, embed_model, device):
    source_alerts = read_alerts(file_path)
    alert_seq = []
    for source_ip in source_alerts:
        for ts, alert in source_alerts[source_ip]:
            if 'set()' in alert[topo_col]:
                continue
            alert[template_col] = clear_content(alert[template_col])
            alert_seq.append((ts, alert))
    alert_seq.sort(key=lambda x: x[0])
    alert_seq = alert_seq[int(len(alert_seq) * train_factor):]
    for ts, alert in alert_seq:
        target_template = alert[template_col]
        target_template_id = alert[template_id_col]
        if target_template_id not in embed_template:
            target_template_v = embed_model.encode([target_template], normalize_embeddings=True)
            target_template_v = torch.tensor(target_template_v, device=device)
            embed_template[target_template_id] = target_template_v
        target_nodes = eval(alert[topo_col])
        alert[topo_col] = target_nodes
        for node_id, node_type in target_nodes:
            query_and_store_k_hops(node_id, k_nodes_dict, edge_node_pair, node_label, k_paths_dict, graph_query,
                                   math.ceil(num_hops / 2.0))
    return alert_seq


def read_label_pair_features(weighted_graph_path, device):
    label_pair_features = np.load(weighted_graph_path, allow_pickle=True).item()
    result = dict()
    for label_pair in label_pair_features:
        features = label_pair_features[label_pair]
        if len(features) == 0:
            continue
        tmp = []
        for template, feature in features:
            feature = torch.tensor(feature, device=device)
            tmp.append(feature)
        result[label_pair] = torch.cat(tmp, dim=0)
    return result


def write_result(file_path, alert_seq, window, num_hops, alpha, thrd):
    file_name = os.path.basename(file_path)
    folder_name = str(window) + '_' + str(num_hops) + '_' + str(int(alpha * 100)) + '_' + str(int(thrd * 100))
    folder_path = os.path.join('output', folder_name)
    if not os.path.exists(folder_path):
        os.mkdir(folder_path)
    file_path = os.path.join(folder_path, file_name)
    output_file_path = file_path.replace('.csv', '_compressed.csv')
    print(output_file_path)
    with open(output_file_path, 'w') as f:
        writer = csv.DictWriter(f, fieldnames=list(alert_seq[0][1].keys()))
        writer.writeheader()
        for ts, alert in alert_seq:
            writer.writerow(alert)


def summarize_no_structural_constraint(alert_file_paths, alert_data, window, num_hops, alpha, thrd, label_pair_features,
                                       gq,
                                       embed_template,
                                       k_paths_dict=dict(), k_nodes_dict=dict(), edges_node_pair=dict(),
                                       node_label=dict(),
                                       topo_col='拓扑节点', serial_id_col='id'):
    common_edge_dict = dict()
    similarity = dict()
    incident_node_degree = dict()
    incident_col = 'incident_id'
    correlate_col = '关联告警ID'
    path_endnode_col = '关联路径端点'
    template_score_col = '语义相似度'
    path_score_col = '路径相似度'
    result = []
    info = False
    for file_path in alert_file_paths:
        incident_id = 0
        print(file_path)
        logging.critical(
            os.path.basename(file_path) + ' ' + str(window) + ' ' + str(num_hops) + ' ' + str(thrd) + ' ' + str(alpha))
        start_time = datetime.datetime.now()
        alert_seq = alert_data[file_path]
        end_time = datetime.datetime.now()
        prepare_time = (end_time - start_time).total_seconds()
        print('prepare data time cost', prepare_time)
        # logging.critical('prepare data time cost ' + str(prepare_time))
        previous_alerts = deque()
        start_time = datetime.datetime.now()
        print(datetime.datetime.now())
        for i in range(len(alert_seq)):
            if info:
                one_start = datetime.datetime.now()
            if i % 200 == 0:
                print(i, len(alert_seq))
            target_ts, target_alert = alert_seq[i]
            target_alert[correlate_col] = ''
            target_alert[path_endnode_col] = ''
            target_alert[template_score_col] = ''
            target_alert[path_score_col] = ''
            target_template_id = target_alert[template_id_col]
            target_template_v = embed_template[target_template_id]
            target_nodes = target_alert[topo_col]
            while len(previous_alerts) > 0 and previous_alerts[0][0] < target_ts - datetime.timedelta(minutes=window):
                previous_alerts.popleft()
            if len(previous_alerts) == 0:
                target_alert[incident_col] = incident_id
                incident_id += 1
                previous_alerts.append((target_ts, target_alert))
                continue
            max_score = -1
            max_template_score = None
            max_path_score = None
            max_score_alert = None
            max_path = None
            neo4j_time = 0
            measure_path_time = 0
            choose_path_time = 0
            prepare_path_time = 0
            check_union_time = 0
            if info:
                one_end = datetime.datetime.now()
                part1_time = (one_end - one_start).total_seconds()
                two_start = datetime.datetime.now()
            for other_ts, other_alert in previous_alerts:
                if info:
                    tmp_start = datetime.datetime.now()
                other_template_id = other_alert[template_id_col]
                other_template_v = embed_template[other_template_id]
                other_nodes = other_alert[topo_col]
                # template_score = (target_template_v @ other_template_v.T)[0][0]
                id_tuple = [target_template_id, other_template_id]
                id_tuple.sort()
                id_tuple = tuple(id_tuple)
                if id_tuple in similarity:
                    template_score = similarity[id_tuple]
                else:
                    template_score = torch.matmul(target_template_v, other_template_v.T)[0][0].item()
                    similarity[id_tuple] = template_score
                if info:
                    tmp_end = datetime.datetime.now()
                    prepare_path_time += (tmp_end - tmp_start).total_seconds()
                    tmp_start = datetime.datetime.now()
                if len(target_nodes & other_nodes) > 0:
                    max_score = template_score * alpha + (1 - alpha)
                    max_score_alert = other_alert
                    max_template_score = template_score
                    max_path_score = 1.0
                    max_path = None
                    continue
                if info:
                    tmp_end = datetime.datetime.now()
                    check_union_time += (tmp_end - tmp_start).total_seconds()
                    tmp_start = datetime.datetime.now()
                common_paths = query_and_store_common_paths(target_nodes, other_nodes, common_edge_dict,
                                                            k_nodes_dict,
                                                            edges_node_pair, node_label, k_paths_dict, gq,
                                                            num_hops)
                if info:
                    tmp_end = datetime.datetime.now()
                    neo4j_time += (tmp_end - tmp_start).total_seconds()
                    tmp_start = datetime.datetime.now()
                path_score, tmp_path = choose_tagged_path(target_template_v, other_template_v, label_pair_features,
                                                          common_paths, node_label)
                if tmp_path is None:
                    continue
                if info:
                    tmp_end = datetime.datetime.now()
                    choose_path_time += (tmp_end - tmp_start).total_seconds()
                total_score = template_score * alpha + (1.0 - alpha) * path_score
                if total_score > max_score:
                    max_score = total_score
                    max_template_score = template_score
                    max_path_score = path_score
                    max_score_alert = other_alert
                    max_path = tmp_path
                    # print(max_path)
                if info:
                    tmp_end = datetime.datetime.now()
                    measure_path_time += (tmp_end - tmp_start).total_seconds()
            if info:
                two_end = datetime.datetime.now()
                part2_time = (two_end - two_start).total_seconds()
                three_start = datetime.datetime.now()

            target_alert[template_score_col] = max_template_score
            target_alert[path_score_col] = max_path_score
            if max_score < thrd:
                target_alert[incident_col] = incident_id
                incident_id += 1
                previous_alerts.append((target_ts, target_alert))
            else:
                cur_incident = max_score_alert[incident_col]
                target_alert[incident_col] = cur_incident
                target_alert[correlate_col] = max_score_alert[serial_id_col]
                previous_alerts.append((target_ts, target_alert))
                if max_path is not None:
                    target_alert[path_endnode_col] = max_path
                    if cur_incident not in incident_node_degree:
                        incident_node_degree[cur_incident] = dict()
                    for u, v in max_path:
                        if u not in incident_node_degree[cur_incident]:
                            incident_node_degree[cur_incident][u] = [0, 0]
                        if v not in incident_node_degree[cur_incident]:
                            incident_node_degree[cur_incident][v] = [0, 0]
                        incident_node_degree[cur_incident][u][1] += 1
                        incident_node_degree[cur_incident][v][0] += 1
            if info:
                three_end = datetime.datetime.now()
                part3_time = (three_end - three_start).total_seconds()
                one_end = datetime.datetime.now()
                one_time = (one_end - one_start).total_seconds()
                print(i, one_time * 1000, neo4j_time * 1000, neo4j_time / one_time, measure_path_time * 1000,
                      measure_path_time / one_time, choose_path_time * 1000, choose_path_time / one_time)
                print(part1_time * 1000, part2_time * 1000, part3_time * 1000)
                print(one_time * 1000, prepare_path_time * 1000, check_union_time * 1000, neo4j_time * 1000,
                      measure_path_time * 1000, choose_path_time * 1000)
        end_time = datetime.datetime.now()
        time_cost = (end_time - start_time).total_seconds()
        compress_ratio = round((1 - (incident_id * 1.0 / len(alert_seq))) * 100, 2)
        incident_num = incident_id
        alert_num = len(alert_seq)
        result.append((file_path, incident_num, alert_num, compress_ratio, time_cost))
        print(incident_num, alert_num, compress_ratio, prepare_time, time_cost)
        logging.critical(str(incident_num) + ' ' + str(alert_num) + ' ' + str(compress_ratio) + ' ' + str(
            prepare_time, ) + ' ' + str(time_cost))
        write_result(file_path, alert_seq, window, num_hops, alpha, thrd)

    for file_path, incident_num, alert_num, compress_ratio, time_cost in result:
        print(file_path)
        print(incident_num, alert_num, compress_ratio, time_cost)


def grid():
    k_paths_dict = dict()
    k_nodes_dict = dict()
    edges_node_pair = dict()
    node_label = dict()
    window = 15
    num_hops = 2
    device = torch.device('cuda:2')
    embed_model = SentenceTransformer(model_path, device='cuda:2')
    print('+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++')
    gq = graph_query('bolt://XX.XX.XX.XX:XXXX', 'XXXXX', 'XXXXXX')
    print('-----------------------------------------------------------')
    label_pair_features = read_label_pair_features(weighted_graph_path, device)
    alert_data = dict()
    embed_template = dict()
    for file_path in alert_file_paths:
        alert_seq = prepare_input_data(file_path, train_factor, template_col, template_id_col, topo_col, k_nodes_dict,
                                       edges_node_pair,
                                       node_label,
                                       k_paths_dict, gq, num_hops, embed_template, embed_model, device)
        alert_data[file_path] = alert_seq
        print('ok', file_path)

    thrd = 0.88
    alpha = 0.7
    summarize_no_structural_constraint(alert_file_paths, alert_data, window, num_hops, alpha, thrd, label_pair_features,
                                       gq, embed_template,
                                       k_paths_dict, k_nodes_dict, edges_node_pair, node_label,
                                       topo_col, template_col)


if __name__ == '__main__':
    alert_file_paths = [
        '.../alert_data.csv'
    ]
    train_factor = 0.8
    weighted_graph_path = '.../edge_anomaly_feature_no_limit.npy'
    model_path = '.../bge_model'
    topo_col = '拓扑节点'
    template_col = 'EventTemplate'
    template_id_col = 'EventId'
    grid()
