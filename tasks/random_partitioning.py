import os
import logging
import random
from datetime import datetime

import networkx as nx
import globals
from tasks.base_partitioner import BasePartitioner
from utils.scoring_manager import ScoringManager


class RandomPartitioner(BasePartitioner):
    def __init__(self):
        super().__init__()

    def random_partition(self, CG, main_v, K):
        partitions = [set() for _ in range(K)]
        nodes = list(CG.nodes)

        if main_v in nodes:
            nodes.remove(main_v)
        random.shuffle(nodes)

        for idx, node in enumerate(nodes):
            partitions[idx % K].add(node)

        for part in partitions:
            part.add(main_v)

        return [list(part) for part in partitions]

    def partition(self, CG, main_v, v_fname_dict, fname_src_dict, fname_bbs_dict,
                  K, out_folder, deleted_pairs, scoring_manager=None, use_unit_diameter=False):
        logging.info("[Paritioning] Running Random partitioning at: %s", datetime.now().strftime("%d/%m/%Y %H:%M:%S"))

        scoring_manager = self.prepare_scores(CG, scoring_manager)
        tasks = self.random_partition(CG, main_v, K)

        task_diameters = {}
        unreachable_tasks = []

        for tIndex, task in enumerate(tasks, start=1):
            fout = open(os.path.join(out_folder, f"task_{tIndex}.txt"), 'w')
            outputSet = set()
            task_score = 0
            diameter = 0  # Always zero for RandomPartitioner
            task_diameters[tIndex] = diameter

            for v in task:
                task_score += CG.nodes[v].get('score', 0)
                colorIndex = (tIndex - 1) % (globals.COLOR_COUNT - 1)
                CG.nodes[v]['color'] = globals.colors[colorIndex]
                CG.nodes[v]['fontcolor'] = globals.colors[colorIndex]

                for (src, dst) in CG.out_edges(v):
                    CG.edges[src, dst]['color'] = globals.colors[colorIndex]

                functionName = v_fname_dict[v]
                try:
                    for (srcFileName, _) in fname_src_dict[functionName]:
                        outputSet.add((srcFileName, functionName))
                except KeyError:
                    pass

            for (srcFileName, functionName) in outputSet:
                fout.write(f"{srcFileName}:{functionName}\n")
            # for (srcFileName, functionName) in deleted_pairs:
            #     fout.write(f"{srcFileName}:{functionName}\n")
            fout.close()

            logging.info("Task %d: %d nodes, score = %d, diameter = %d",
                         tIndex, len(task), task_score, diameter)

        with open(os.path.join(out_folder, "task_diameters.txt"), 'w') as f:
            for tidx, d in task_diameters.items():
                f.write(f"task_{tidx}: {d}\n")

        nx.drawing.nx_pydot.write_dot(CG, os.path.join(out_folder, "cg.dot"))
        logging.info("[Paritioning] Random partitioning completed at: %s", datetime.now().strftime("%d/%m/%Y %H:%M:%S"))
