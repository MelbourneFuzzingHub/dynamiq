import logging
import math
from datetime import datetime
from tasks.base_partitioner import BasePartitioner

class HDRFPartitioner(BasePartitioner):
    def __init__(self, lambda_param=1.0, epsilon=1e-6):
        super().__init__()
        self.lambda_param = lambda_param
        self.epsilon = epsilon

    def hdrf_partition_score(self, CG, K):
        partitions = [set() for _ in range(K)]
        partition_loads = [0.0 for _ in range(K)]
        total_score = sum(CG.nodes[v].get('score', 1.0) for v in CG.nodes)

        edges = list(CG.edges)
        for u, v in edges:
            score_u = CG.nodes[u].get('score', 1.0)
            score_v = CG.nodes[v].get('score', 1.0)
            theta_u = score_u / (score_u + score_v + self.epsilon)
            theta_v = 1 - theta_u

            best_score = -float("inf")
            best_partition = None

            maxsize = max(partition_loads)
            minsize = min(partition_loads)
            denominator = self.epsilon + (maxsize - minsize)

            for p in range(K):
                g_u = 1 + (1 - theta_u) if u in partitions[p] else 0
                g_v = 1 + (1 - theta_v) if v in partitions[p] else 0

                c_rep = g_u + g_v
                c_bal = self.lambda_param * (maxsize - partition_loads[p]) / denominator
                total = c_rep + c_bal

                if total > best_score:
                    best_score = total
                    best_partition = p

            for node in [u, v]:
                if node not in partitions[best_partition]:
                    partitions[best_partition].add(node)
                    partition_loads[best_partition] += CG.nodes[node].get('score', 1.0)

        return [list(part) for part in partitions]

    def partition(self, CG, main_v, v_fname_dict, fname_src_dict, fname_bbs_dict,
                  K, out_folder, deleted_pairs, scoring_manager=None, use_unit_diameter=False):
        logging.info("[Paritioning] Running HDRF partitioning at: %s", datetime.now().strftime("%d/%m/%Y %H:%M:%S"))

        scoring_manager = self.prepare_scores(CG, scoring_manager)
        tasks = self.hdrf_partition_score(CG, K)

        self.write_output(CG, tasks, main_v, v_fname_dict, fname_src_dict,
                          fname_bbs_dict, out_folder, deleted_pairs, use_unit_diameter)
        logging.info("[Paritioning] Finished HDRF partitioning at: %s", datetime.now().strftime("%d/%m/%Y %H:%M:%S"))