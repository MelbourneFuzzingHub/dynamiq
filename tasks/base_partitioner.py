import os
import logging
import math
import networkx as nx
from abc import ABC, abstractmethod
from utils.scoring_manager import ScoringManager
import globals

class BasePartitioner(ABC):
    def __init__(self):
        self.scoring_method = "entropy_weighted"

    def prepare_scores(self, CG, scoring_manager=None):
        scoring_manager = scoring_manager or ScoringManager(graph=CG)
        scoring_manager.set_method(self.scoring_method)

        scores = []
        for v in CG.nodes:
            score = scoring_manager.calculate_score(CG.nodes[v], v)
            CG.nodes[v]['score'] = score
            scores.append(score)

        logging.info("[Paritioning] Total score of all nodes: %d", sum(scores))
        return scoring_manager

    def enrich_with_path(self, CG, main_v, v, v_fname_dict, fname_src_dict, outputSet):
        """Add all source:func pairs on the path from main_v to v into outputSet."""
        added_count = 0
        if nx.has_path(CG, main_v, v):
            try:
                path = nx.shortest_path(CG, main_v, v)
                for v1 in path:
                    fname = v_fname_dict[v1]
                    try:
                        for (srcFileName, _) in fname_src_dict[fname]:
                            if (srcFileName, fname) not in outputSet:
                                outputSet.add((srcFileName, fname))
                                added_count += 1
                    except KeyError:
                        continue
            except nx.NetworkXNoPath:
                logging.info(f"[Paritioning] No path from {main_v} to {v}")
        return added_count

    def write_output(
        self, CG, tasks, main_v, v_fname_dict, fname_src_dict, fname_bbs_dict,
        out_folder, deleted_pairs, use_unit_diameter=False
    ):
        HANDLE_SINGLETONS = True
        ENRICH_ALL_REACHABLE = False

        task_diameters = {}
        unreachable_tasks = []

        for tIndex, task in enumerate(tasks, start=1):
            fout = open(os.path.join(out_folder, f"task_{tIndex}.txt"), 'w')
            outputSet = set()
            task_score = 0
            reachable = False
            total_added_from_main_path = 0

            subgraph = CG.subgraph(task)
            try:
                if use_unit_diameter:
                    diameter = 2
                if nx.is_connected(subgraph.to_undirected()):
                    diameter = round(nx.average_shortest_path_length(subgraph.to_undirected()))
                else:
                    diameter = round(max(
                        nx.average_shortest_path_length(subgraph.subgraph(c).to_undirected())
                        for c in nx.connected_components(subgraph.to_undirected())
                    ))
                # elif nx.is_connected(subgraph.to_undirected()):
                #     diameter = nx.diameter(subgraph.to_undirected())
                # else:
                #     diameter = max(
                #         nx.diameter(subgraph.subgraph(c).to_undirected())
                #         for c in nx.connected_components(subgraph.to_undirected())
                #     )
            except nx.NetworkXError as e:
                diameter = 0
                logging.warning(f"[Paritioning] Could not compute diameter for task {tIndex}: {e}")

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

            if HANDLE_SINGLETONS:
                components = list(nx.connected_components(subgraph.to_undirected()))
                isolated_nodes = [list(c)[0] for c in components if len(c) == 1]
                logging.info(f"[Paritioning] Task {tIndex} has {len(isolated_nodes)} singleton node(s)")
                for v in isolated_nodes:
                    total_added_from_main_path += self.enrich_with_path(CG, main_v, v, v_fname_dict, fname_src_dict, outputSet)
                if total_added_from_main_path == 0:
                    for v in task:
                        if not reachable and nx.has_path(CG, main_v, v):
                            reachable = True
                            total_added_from_main_path += self.enrich_with_path(CG, main_v, v, v_fname_dict, fname_src_dict, outputSet)
            else:
                for v in task:
                    if ENRICH_ALL_REACHABLE:
                        if nx.has_path(CG, main_v, v):
                            reachable = True
                            total_added_from_main_path += self.enrich_with_path(CG, main_v, v, v_fname_dict, fname_src_dict, outputSet)
                    else:
                        if not reachable and nx.has_path(CG, main_v, v):
                            reachable = True
                            total_added_from_main_path += self.enrich_with_path(CG, main_v, v, v_fname_dict, fname_src_dict, outputSet)

                if not reachable:
                    unreachable_tasks.append(tIndex)

            for (srcFileName, functionName) in outputSet:
                fout.write(f"{srcFileName}:{functionName}\n")
            for (srcFileName, functionName) in deleted_pairs:
                fout.write(f"{srcFileName}:{functionName}\n")
            fout.close()

            logging.info("[Paritioning] Task %d: %d nodes, score = %d, diameter = %d, added_from_main_path = %d",
                         tIndex, len(task), task_score, task_diameters[tIndex], total_added_from_main_path)

        with open(os.path.join(out_folder, "task_diameters.txt"), 'w') as f:
            for tidx, d in task_diameters.items():
                f.write(f"task_{tidx}: {d}\n")

        if not HANDLE_SINGLETONS and unreachable_tasks:
            logging.warning(f"[Paritioning] Tasks unreachable from main: {unreachable_tasks}")

        nx.drawing.nx_pydot.write_dot(CG, os.path.join(out_folder, "cg.dot"))

    @abstractmethod
    def partition(self, CG, main_v, v_fname_dict, fname_src_dict, fname_bbs_dict,
                  K, out_folder, deleted_pairs, scoring_manager=None, use_unit_diameter=False):
        """
        Abstract method to be implemented by derived classes.
        """
        pass
