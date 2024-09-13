import datetime
import random
import ast
from sklearn.cluster import DBSCAN
import numpy as np
import json
from sentence_transformers import SentenceTransformer


def cluster_anomalies(anomalies):
    clustering = DBSCAN(eps=1,min_samples=2, metric='cosine').fit(anomalies)
    return clustering


def cluster(model_file_path, label_pair_data_path, result_file_path):
    embed_model = SentenceTransformer(model_file_path,device='cuda:1')
    lines = []
    with open(label_pair_data_path, 'r') as f:
        for line in f:
            lines.append(line)
    label_pair_features = dict()
    for line in lines:
        data = eval(line)
        label_pair = list(data.keys())[0]
        features = []
        weight = []
        templates = []
        for template in data[label_pair]:
            cnt = data[label_pair][template]
            feature = embed_model.encode([template], normalize_embeddings=True)
            features.append(feature)
            weight.append(cnt)
            templates.append((template, feature))
        weight = np.array(weight)
        features = np.stack(features)
        features = np.squeeze(features,axis=1)
        clustering = DBSCAN(eps=0.3, min_samples=2, metric='cosine').fit(features, sample_weight=weight)
        tmp = []
        for i, label in enumerate(clustering.labels_):
            if label < 0:
                continue
            tmp.append(templates[i])
        label_pair_features[label_pair] = tmp
    np.save(result_file_path, label_pair_features, allow_pickle=True)

if __name__ == '__main__':
    model_path = '.../bge_model'
    label_pair_data_path = '.../label_pair_data.jsonl'
    result_file_path = '.../edge_anomaly_feature.npy'

    start = datetime.datetime.now()
    cluster(model_path, label_pair_data_path, result_file_path)
    end = datetime.datetime.now()
    duration = (end-start).total_seconds()
    print('clustering time cost (s)', duration)