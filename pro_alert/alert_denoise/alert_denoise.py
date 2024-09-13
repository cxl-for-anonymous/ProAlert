import random
import re
import csv
import datetime
import json
from collections import deque
from topo_read.topo_read import graph_query

def get_value(row, key):
    if key in row:
        return row[key]
    if key != key.lower() and key.lower() in row:
        row[key] = row[key.lower()]
        row.pop(key.lower())
        return row[key]
    return None

def read_alert_file(file_path, ts_col, ts_format, ip_col, template_col, info_col):
    pattern = re.compile(r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+')
    source_alarm_seq = dict()
    with open(file_path, 'r') as f:
        reader = csv.DictReader(f)
        for alarm in reader:
            ts = get_value(alarm, ts_col)
            if None is ts or '' == ts.strip():
                continue
            if ts is None or len(ts.strip()) == 0 or '+08:00' not in ts:
                ts = datetime.datetime.now().strftime(ts_format)
            if '.' in ts:
                ts = datetime.datetime.strptime(ts, ts_format)
            else:
                ts = datetime.datetime.strptime(ts, ts_format)
            content = get_value(alarm, template_col)
            if None is content or '' == content.strip():
                continue
            content_ips = list(set(pattern.findall(content)))
            alarm['content_ip'] = content_ips
            info_ip = None
            info_cloud = None
            info = get_value(alarm, info_col)
            if None is not info and info.endswith('}'):
                info = info.replace('true','True')
                info = info.replace('false','False')
                info = eval(info)
                info_ip_key = 'ip'
                if 'agent_address' in info:
                    info_ip_key = 'agent_address'
                for info_k in info:
                    if info_ip_key in info_k.lower():
                        info_ip = info[info_k]
                    if 'cloud' in info_k.lower() and 'id' in info_k.lower():
                        info_cloud = int(info[info_k])
            source_ip = (get_value(alarm, ip_col), info_ip, info_cloud)
            if source_ip not in source_alarm_seq:
                source_alarm_seq[source_ip] = []
            source_alarm_seq[source_ip].append((ts, alarm))
    for source_ip in source_alarm_seq:
        source_alarm_seq[source_ip].sort(key=lambda x: x[0])
    return source_alarm_seq

def read_alerts(file_path):
    timestamp_column = 'alertDt'
    timestamp_format = '%Y-%m-%dT%H:%M:%S.%f+08:00'
    ip_column = 'ipAddr'
    template_column = 'EventTemplate'
    info_column = 'alarmDimension'
    source_alerts = read_alert_file(file_path, timestamp_column, timestamp_format, ip_column, template_column, info_column)
    return source_alerts


def get_alert_node():
    alert_file_path = [

    ]
    graph = graph_query('bolt://localhost:7687', 'neo4j', '123456789')
    for file_path in alert_file_path:
        print(file_path)
        field_names = None
        source_alerts = read_alerts(file_path)
        alert_seq = []
        for source_ip in source_alerts:
            alert_cloud_ip, alert_physic_ip, alert_cloud = source_ip
            topo_nodes = graph.query_nodes(alert_cloud_ip,alert_physic_ip,alert_cloud)
            for ts, alert in source_alerts[source_ip]:
                alert['拓扑节点'] = str(topo_nodes)
                if not field_names:
                    field_names = list(alert.keys())
                alert_seq.append((ts, alert))
        alert_seq.sort(key=lambda x:x[0])
        output_file_path = file_path.replace('.csv','_tagged_topo_node.csv')
        with open(output_file_path, 'w') as f:
            writer = csv.DictWriter(f, field_names)
            writer.writeheader()
            for ts,alert in alert_seq:
                writer.writerow(alert)
            f.flush()

def get_node_alerts(alert_seq, topo_col):
    node_alerts = dict()
    for ts, alert in alert_seq:
        nodes = eval(alert[topo_col])
        for node_info in nodes:
            if node_info not in node_alerts:
                node_alerts[node_info] = []
            node_alerts[node_info].append((ts, alert))
    return node_alerts

def get_alert_position(alert_seq, serial_key):
    alert_position = dict()
    for i, (ts, alert) in enumerate(alert_seq):
        alert_position[alert[serial_key]] = i
    return alert_position

def resort_alerts(window, num_hops, factor, topo_col = '拓扑节点', candidate_col='candidate_group'):
    alert_file_path = [
        '.../alert_data.csv'
    ]
    gq = graph_query('bolt://localhost:7687', 'neo4j', '123456789')
    serial_number = 0
    serial_number_key = 'serial_number'
    connected_alert_key = 'connected_alert'
    k_hops_dict = dict()
    candidate_group = 0
    for file_path in alert_file_path:
        print(file_path)
        source_alerts = read_alerts(file_path)
        alert_seq = []
        for source_ip in source_alerts:
            for ts_start, alert in source_alerts[source_ip]:
                serial_number += 1
                alert[serial_number_key] = serial_number
                alert[connected_alert_key] = serial_number
                alert_seq.append((ts_start, alert))
        alert_seq.sort(key=lambda x:x[0])
        print(len(alert_seq), int(len(alert_seq) * factor))
        alert_seq = alert_seq[:int(len(alert_seq) * factor)]
        node_alerts = get_node_alerts(alert_seq,topo_col)
        alert_pos = get_alert_position(alert_seq, serial_number_key)
        visited = set()
        new_alert_seq = []
        for i in range(len(alert_seq)):
            if alert_seq[i][1][serial_number_key] in visited:
                continue
            visited.add(alert_seq[i][1][serial_number_key])
            print(i, len(alert_seq), alert_seq[i][1]['id'])
            dque = deque()
            dque.append((i, alert_seq[i][0], alert_seq[i][0] - datetime.timedelta(minutes=window), alert_seq[i][0] + datetime.timedelta(minutes=window),alert_seq[i][1]))
            candidates = [alert_seq[i]]
            while len(dque) > 0:
                pos, ts, ts_start, ts_end, alert = dque.popleft()
                nodes = eval(alert[topo_col])
                k_hops = set()
                k_hops.update(nodes)
                for node_id, node_type in nodes:
                    if node_id in k_hops_dict:
                        k_hops.update(k_hops_dict[node_id])
                    else:
                        tmp = gq.query_k_neighbors(node_id, num_hops)
                        k_hops.update(tmp)
                        k_hops_dict[node_id] = tmp
                for j in range(pos+1, len(alert_seq)):
                    other_ts, other_alert = alert_seq[j]
                    if other_alert[serial_number_key] in visited:
                        continue
                    if other_ts > ts_end:
                        break
                    if other_ts < ts_start:
                        continue
                    other_nodes = eval(other_alert[topo_col])
                    common_nodes = k_hops & other_nodes
                    if len(common_nodes) > 0:
                        for c_node in common_nodes:
                            min_ts = None
                            max_ts = None
                            tmp_alert = None
                            used_alerts = []
                            for k in range(len(node_alerts[c_node])):
                                c_ts, c_alert = node_alerts[c_node][k]
                                if c_alert[serial_number_key] in visited:
                                    used_alerts.append((c_ts, c_alert))
                                    continue
                                if c_ts > ts_end:
                                    break
                                if c_ts < ts_start:
                                    continue
                                visited.add(c_alert[serial_number_key])
                                candidates.append((c_ts,c_alert))
                                c_alert[connected_alert_key] = alert[serial_number_key]
                                used_alerts.append((c_ts,c_alert))
                                if not min_ts:
                                    min_ts = c_ts
                                    max_ts = c_ts
                                    tmp_alert = c_alert
                                min_ts = min(min_ts, c_ts)
                                max_ts = max(max_ts, c_ts)
                            for used_alert in used_alerts:
                                node_alerts[c_node].remove(used_alert)
                            if tmp_alert is not None:
                                dque.append((alert_pos[tmp_alert[serial_number_key]], min_ts, min_ts - datetime.timedelta(minutes=window), max_ts + datetime.timedelta(minutes=window), tmp_alert))
            for ts_start, alert in candidates:
                alert[candidate_col] = candidate_group
            candidate_group += 1
            candidates.sort(key=lambda x:x[0])
            new_alert_seq.extend(candidates)
        output_file_path = file_path.replace('.csv','_resort.csv')
        field_names = list(new_alert_seq[0][1].keys())
        with open(output_file_path, 'w') as f:
            writer = csv.DictWriter(f, field_names)
            writer.writeheader()
            for ts_start,alert in new_alert_seq:
                writer.writerow(alert)
            f.flush()

def clear_content(ret):
    ret = ret.replace('<\d>', ' ').replace('<*>',' ').replace('\"',' ').replace('/',' ').replace(';',' ').replace(',',' ').replace('：',' ')
    ret = ret.replace(':', ' ').replace('[ ]',' ').replace('[ _ ]', '').replace('[ __ ]', '').replace('[ - ]', '').replace('[ -- ]', '')
    ret = ret.replace('[', ' ').replace(']',' ').replace('+', '').replace('-', '').replace('_', '').replace('=', '')
    while '  ' in ret:
        ret = ret.replace('  ', ' ')
    ret = ret.strip()
    return ret



def get_training_files_naive(window = 5, num_hops=3, content_col = 'EventTemplate', template_col = 'EventTemplate', topo_col = '拓扑节点', candidate_col='candidate_group', negative_num=1):
    alert_file_path = [
        '.../alert_data.csv'
    ]
    gq = graph_query('bolt://localhost:7687', 'neo4j', '123456789')
    serial_number = 0
    serial_number_key = 'serial_number'
    train_data = []
    average_length = 0
    for file_path in alert_file_path:
        print(file_path)
        field_names = None
        source_alerts = read_alerts(file_path)
        alert_seq = []
        for source_ip in source_alerts:
            for ts, alert in source_alerts[source_ip]:
                serial_number += 1
                alert[serial_number_key] = serial_number
                alert_seq.append((ts, alert))
                if not field_names:
                    field_names = list(alert.keys())
        k_hops_dict = dict()
        visited = dict()
        file_num_samples = 0
        for i in range(len(alert_seq)):
            # print(i, len(alert_seq))
            ts, alert = alert_seq[i]
            positives = set()
            slice_end = i
            nodes = eval(alert[topo_col])
            k_hops = set()
            k_hops.update(nodes)
            if alert[candidate_col] not in visited:
                visited[alert[candidate_col]] = set()
            for node_id, node_type in nodes:
                if node_id in k_hops_dict:
                    k_hops.update(k_hops_dict[node_id])
                else:
                    tmp = gq.query_k_hops(node_id, num_hops)
                    k_hops.update(tmp)
                    k_hops_dict[node_id] = tmp
            for j in range(i+1, len(alert_seq)):
                other_ts, other_alert = alert_seq[j]
                if ts + datetime.timedelta(minutes=window) <= other_ts:
                    break
                if other_alert[candidate_col] != alert[candidate_col]:
                    break
                if get_value(alert, content_col) == get_value(other_alert, content_col):
                    continue
                tmp = (get_value(alert, content_col), get_value(other_alert, content_col))
                tmp2 = (get_value(other_alert, content_col), get_value(alert, content_col))
                # print(tmp)
                # print(visited)
                if tmp in visited[alert[candidate_col]] or tmp2 in visited[alert[candidate_col]]:
                    continue
                other_nodes = eval(other_alert[topo_col])
                if len(other_nodes & k_hops) == 0:
                    continue
                visited[alert[candidate_col]].add(tmp)
                visited[alert[candidate_col]].add(tmp2)
                positives.add(get_value(other_alert,content_col))
                slice_end = j
            negatives = set()
            cnt = 0
            max_sample_times = 3 * negative_num
            if len(positives) == 0:
                continue
            while (len(negatives) != len(positives) * negative_num and cnt < max_sample_times) or len(negatives) == 0:
                cnt += 1
                k = random.randint(0, len(alert_seq)-1)
                if i <= k <= slice_end:
                    k = min(len(alert_seq) - 1, k-i + slice_end + 1)
                other_ts, other_alert = alert_seq[k]
                if other_alert[candidate_col] == alert[candidate_col]:
                    continue
                if other_alert[template_col] == alert[template_col]:
                    continue
                if get_value(other_alert, content_col) in positives:
                    continue
                negatives.add(get_value(other_alert,content_col))
            positives = list(positives)
            negatives = list(negatives)
            while len(negatives) < negative_num * len(positives):
                tmp = negatives
                negatives.extend(tmp)
            negatives = [clear_content(x) for x in negatives]
            positives = [clear_content(x) for x in positives]
            for j, pos_alert in enumerate(positives):
                output_line = dict()
                output_line["query"] = clear_content(get_value(alert,content_col))
                average_length += len(clear_content(get_value(alert,content_col)))
                output_line["pos"] = [pos_alert]
                output_line["neg"] = negatives[j * negative_num:(j+1)*negative_num]
                train_data.append(output_line)
                file_num_samples+=1
        print(file_num_samples)
    output_file_path = '.../train_data.jsonl'
    random.shuffle(train_data)
    average_length = average_length * 1.0 / len(train_data)
    print('average length', average_length)
    with open(output_file_path, 'w') as f:
        for row in train_data:
            row = json.dumps(row, ensure_ascii=False)
            f.writelines([str(row)])
            f.write('\n')
        f.flush()

if __name__ =='__main__':
    get_alert_node()
    resort_alerts(15,2, 0.8)