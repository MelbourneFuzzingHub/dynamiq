import logging
import math
from datetime import datetime
from tasks.base_partitioner import BasePartitioner

class LDGPartitioner(BasePartitioner):
    def __init__(self, connectivity_weight=1.0, penalty_weight=0.75):
        super().__init__()
        self.connectivity_weight = connectivity_weight
        self.penalty_weight = penalty_weight

    def ldg_partition_score(self, CG, K, capacity):
        """
        LDG partitioning with stricter load enforcement and limited connectivity influence.
        """
        partitions = [[] for _ in range(K)]
        partition_loads = [0] * K  # Track current load of each partition

        for v in sorted(CG.nodes, key=lambda x: CG.nodes[x].get('score', 0), reverse=True):
            best_partition = None
            best_score = -float('inf')
            node_score = CG.nodes[v].get('score', 0)
            fallback_partition = min(range(K), key=lambda i: partition_loads[i])

            for i in range(K):
                # Skip this partition if adding this node would exceed capacity
                if partition_loads[i] + node_score > capacity:
                    continue

                # Calculate the number of neighbors in partition `i`
                neighbors_in_partition = sum(1 for neighbor in CG.neighbors(v) if neighbor in partitions[i]) * self.connectivity_weight # Weigh down connectivity influence

                # Load penalty with stricter enforcement, and reduce influence of neighbors
                load_penalty = (1 - (partition_loads[i] / capacity)) * self.penalty_weight  # Weigh down the load penalty slightly

                # Partition scoring function that balances connectivity and load
                score = neighbors_in_partition * load_penalty  # Weigh down connectivity influence

                # Check if this partition has the highest score for the current node `v`
                if score > best_score:
                    best_score = score
                    best_partition = i

            # Assign node `v` to the best partition and update partition load
            if best_partition is not None:
                partitions[best_partition].append(v)
                partition_loads[best_partition] += node_score
            else:
                # Fallback: add to the least-loaded partition
                partitions[fallback_partition].append(v)
                partition_loads[fallback_partition] += node_score

        return partitions

    def partition(self, CG, main_v, v_fname_dict, fname_src_dict, fname_bbs_dict,
                  K, out_folder, deleted_pairs, scoring_manager=None, use_unit_diameter=False):
        logging.info("[Paritioning] unning LDG partitioning at: %s", datetime.now().strftime("%d/%m/%Y %H:%M:%S"))

        scoring_manager = self.prepare_scores(CG, scoring_manager)
        total_score = sum(CG.nodes[v]['score'] for v in CG.nodes)
        capacity = math.ceil(total_score / K)

        tasks = self.ldg_partition_score(CG, K, capacity)

        self.write_output(CG, tasks, main_v, v_fname_dict, fname_src_dict,
                          fname_bbs_dict, out_folder, deleted_pairs, use_unit_diameter)
        logging.info("[Paritioning] Finished LDG partitioning at: %s", datetime.now().strftime("%d/%m/%Y %H:%M:%S"))
