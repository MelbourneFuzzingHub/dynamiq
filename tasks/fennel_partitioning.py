import logging
import math
from datetime import datetime
from tasks.base_partitioner import BasePartitioner

class FennelPartitioner(BasePartitioner):
    def __init__(self):
        super().__init__()

    def fennel_partition_score(self, CG, K, alpha, gamma=1.5, nu=1.1):
        partitions = [[] for _ in range(K)]
        partition_loads = [0] * K
        total_score = sum(CG.nodes[v].get('score', 1) for v in CG.nodes)
        load_limit = math.ceil(nu * total_score / K)

        nodes = sorted(CG.nodes, key=lambda v: CG.nodes[v].get('score', 0), reverse=True)

        for v in nodes:
            best_partition = None
            best_score = -float('inf')
            node_score = CG.nodes[v].get('score', 0)
            fallback_partition = min(range(K), key=lambda i: partition_loads[i])

            for i in range(K):
                if partition_loads[i] + node_score <= load_limit:
                    neighbors_in_partition = sum(1 for neighbor in CG.neighbors(v) if neighbor in partitions[i])
                    locality_term = neighbors_in_partition
                    load_penalty = alpha * gamma * (partition_loads[i] ** (gamma - 1))
                    score = locality_term - load_penalty

                    if score > best_score:
                        best_score = score
                        best_partition = i

            if best_partition is not None:
                partitions[best_partition].append(v)
                partition_loads[best_partition] += node_score
            else:
                partitions[fallback_partition].append(v)
                partition_loads[fallback_partition] += node_score

        return partitions

    def partition(self, CG, main_v, v_fname_dict, fname_src_dict, fname_bbs_dict,
                  K, out_folder, deleted_pairs, scoring_manager=None, use_unit_diameter=False):
        logging.info("[Paritioning] Running Fennel partitioning at: %s", datetime.now().strftime("%d/%m/%Y %H:%M:%S"))

        scoring_manager = self.prepare_scores(CG, scoring_manager)

        # Compute Fennel parameters
        alpha = math.sqrt(K) * (len(CG.edges) / (len(CG.nodes) ** 1.5))
        gamma = 1.5
        nu = 1.1

        tasks = self.fennel_partition_score(CG, K, alpha, gamma, nu)

        self.write_output(CG, tasks, main_v, v_fname_dict, fname_src_dict, fname_bbs_dict,
                          out_folder, deleted_pairs, use_unit_diameter)
        logging.info("[Paritioning] Finished Fennel partitioning at: %s", datetime.now().strftime("%d/%m/%Y %H:%M:%S"))
