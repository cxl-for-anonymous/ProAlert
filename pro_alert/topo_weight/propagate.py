from topo_read.topo_read import graph_query
from alert_denoise.read_alert import read_alerts
import datetime


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

def resort_alerts(source_alerts, template_col):
    alert_seq = []
    for source_ip in source_alerts:
        for ts, alert in source_alerts[source_ip]:
            alert[template_col] = clear_content(alert[template_col])
            alert_seq.append((ts, alert))
    alert_seq.sort(key=lambda x: x[0])
    return alert_seq


def query_and_store_k_hops(node_id,node_labels, k_nodes_dict, edge_label_pair, k_paths_dict, gq, num_hops):
    if node_id not in k_nodes_dict:
        t_node_labels, neighbor_edges, neighbor_nodes, neighbor_node_paths = gq.query_k_edges(node_id, num_hops)
        edge_label_pair.update(neighbor_edges)
        k_nodes_dict[node_id] = neighbor_nodes
        k_paths_dict[node_id] = neighbor_node_paths
        node_labels.update(t_node_labels)


def query_and_store_common_edges(target_nodes, other_nodes, node_labels, common_edge_dict, k_nodes_dict, edge_label_pair,
                                 k_paths_dict,
                                 gq, num_hops):
    total_nodes = str((target_nodes, other_nodes))
    if total_nodes in common_edge_dict:
        return common_edge_dict[total_nodes]
    total_nodes = str((other_nodes, target_nodes))
    if total_nodes in common_edge_dict:
        return common_edge_dict[total_nodes]
    common_edges = set()
    for node_id, node_type in target_nodes:
        query_and_store_k_hops(node_id, node_labels, k_nodes_dict, edge_label_pair, k_paths_dict, gq, num_hops)
        for other_node_id, other_node_type in other_nodes:
            if node_id == other_node_id:
                continue
            query_and_store_k_hops(other_node_id, node_labels, k_nodes_dict, edge_label_pair, k_paths_dict, gq, num_hops)
            if len(k_nodes_dict[node_id] & k_nodes_dict[other_node_id]) > 0:
                tmp = k_nodes_dict[node_id] & k_nodes_dict[other_node_id]
                for common_node_id in tmp:
                    common_edges.update(k_paths_dict[node_id][common_node_id])
                    common_edges.update(k_paths_dict[other_node_id][common_node_id])
    common_edge_dict[total_nodes] = common_edges
    return common_edges


def propagate_templates(window, num_hops, alert_file_paths, topo_col='拓扑节点', template_col='EventTemplate',
                        candidate_col='candidate_group'):
    gq = graph_query('bolt://XX.XX.XX.XX:XXXX', 'XXXXX', 'XXXXXX')
    edge_to_node_id_pair = dict()
    k_nodes_dict = dict()
    k_paths_dict = dict()
    common_edge_dict = dict()
    node_labels = dict()
    total_edge_templates = dict()
    for file_path in alert_file_paths:
        print(file_path)
        # visited alerts for a label pair
        visited = dict()
        source_alerts = read_alerts(file_path)
        alert_seq = resort_alerts(source_alerts, template_col)
        for i in range(len(alert_seq)):
            target_ts, target_alert = alert_seq[i]
            target_template = target_alert[template_col]
            target_nodes = eval(target_alert[topo_col])
            for j in range(i + 1, len(alert_seq)):
                other_ts, other_alert = alert_seq[j]
                if other_ts > target_ts + datetime.timedelta(minutes=window):
                    break
                if target_alert[candidate_col] != other_alert[candidate_col]:
                    break
                if target_alert[topo_col] == other_alert[topo_col]:
                    continue
                other_template = other_alert[template_col]
                other_nodes = eval(other_alert[topo_col])
                common_edges = query_and_store_common_edges(target_nodes, other_nodes, node_labels, common_edge_dict, k_nodes_dict,
                                                            edge_to_node_id_pair, k_paths_dict, gq, num_hops)
                for common_edge_id in common_edges:
                    node_id1, node_id2 = edge_to_node_id_pair[common_edge_id]
                    label1 = node_labels[node_id1]
                    label2 = node_labels[node_id2]
                    tmp = [label1, label2]
                    tmp.sort()
                    tmp = tuple(tmp)
                    if tmp not in total_edge_templates:
                        total_edge_templates[tmp] = dict()
                    if tmp not in visited:
                        visited[tmp] = set()
                    for alert_pos, template in [(i, target_template), (j, other_template)]:
                        if alert_pos in visited[tmp]:
                            continue
                        visited[tmp].add(alert_pos)
                        if template not in total_edge_templates[tmp]:
                            total_edge_templates[tmp][template] = 0
                        total_edge_templates[tmp][template] += 1
            print(i, len(alert_seq))
        output_file_path = '.../label_pair_data.jsonl'
        with open(output_file_path, 'w') as f:
            for label_pair in total_edge_templates:
                tmp_dict = dict()
                tmp_dict[label_pair] = total_edge_templates[label_pair]
                row = str(tmp_dict)
                f.writelines([str(row)])
                f.write('\n')
            f.flush()

if __name__ == '__main__':
    alert_file_paths = [
        '.../alert_data.csv'
    ]
    start = datetime.datetime.now()
    propagate_templates(5, 2, alert_file_paths)
    end = datetime.datetime.now()
    duration = (end-start).total_seconds()
    print('propagation time cost (s)', duration)