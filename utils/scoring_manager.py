import logging
import math
import networkx as nx
import numpy as np
from sklearn.preprocessing import MinMaxScaler

class ScoringManager:
    def __init__(self, graph=None):
        """Initialize scoring manager with an optional graph."""
        self.scoring_methods = {
            "default": self.default_score,
            "node_degree": self.node_degree_score,
            "logarithmic": self.logarithmic_score,
            "penalized": self.penalized_score,
            "penalized_degree": self.penalized_degree_score,
            "penalized_degree_pagerank": self.penalized_degree_pagerank_score,
            "penalized_degree_centrality": self.penalized_degree_centrality_score,
            "entropy_weighted": self.entropy_weighted_score,
        }
        self.current_method = "penalized_degree"
        self.graph = graph  # Store graph
        self.pagerank_scores = {}  # Cache PageRank
        self.katz_scores = {}  # Cache Katz scores if needed
        self.degree_centrality = {}  # Cache degree centrality
        self.use_katz = True  # Use Katz Centrality instead of Degree Centrality

        # Compute PageRank only if needed
        # if self.current_method == "penalized_degree_pagerank" and self.graph:
        #     self.compute_pagerank()

    def set_method(self, method_name):
        """Set scoring method and compute PageRank if required."""
        if method_name in self.scoring_methods:
            self.current_method = method_name
            logging.info(f"[Paritioning] Scoring method set to: {method_name}")
            
            # Compute PageRank only if using penalized_degree_pagerank
            if method_name == "penalized_degree_pagerank" and self.graph:
                self.compute_pagerank()
            # Compute centrality if using penalized_degree
            if method_name in {"penalized_degree_centrality", "entropy_weighted"}:
                self.compute_centrality()
        else:
            raise ValueError(f"Unknown scoring method: {method_name}")

    def compute_pagerank(self, alpha=0.85):
        """Compute and normalize PageRank scores."""
        if self.current_method != "penalized_degree_pagerank":
            return  # Skip computation if not needed

        if self.graph:
            self.pagerank_scores = nx.pagerank(self.graph, alpha=alpha)
            self.normalize_pagerank_scores()  # Apply scaling
            logging.debug("PageRank scores computed and normalized.")
        else:
            logging.warning("Graph not available for PageRank computation.")

    def compute_centrality(self):
        """Compute Degree Centrality or Katz Centrality based on configuration."""
        if self.use_katz:
            self.katz_scores = nx.katz_centrality(self.graph, alpha=0.1, beta=1.0, max_iter=1000)
        else:
            self.degree_centrality = nx.degree_centrality(self.graph)  # Normalized degree
            self.normalize_centrality_scores(self.degree_centrality)  # Apply scaling
            logging.debug("Centrality scores computed and normalized.")

    def calculate_score(self, node_data, node):
        """Calculate score for a node using the selected method."""
        if self.current_method == "penalized_degree_pagerank":
            if not self.pagerank_scores:  # Ensure PageRank is available
                self.compute_pagerank()
            return self.penalized_degree_pagerank_score(node_data, self.graph, node, self.pagerank_scores)
        else:
            return self.scoring_methods[self.current_method](node_data, self.graph, node)


    def default_score(self, node_data, graph=None, node=None):
        """Default score based on basic blocks."""
        bcovered_pre = node_data.get('bcovered_pre', 0)
        bcovered_cur = node_data.get('bcovered_cur', 0)
        btotal = node_data.get('btotal', 0)
        return (bcovered_cur - bcovered_pre + 1) * (btotal - bcovered_cur + 1)

    def logarithmic_score(self, node_data, graph=None, node=None):
        """ Score with logarithmic scaling. """
        bcovered_cur = node_data.get('bcovered_cur', 0)
        bcovered_pre = node_data.get('bcovered_pre', 0)
        btotal = node_data.get('btotal', 0)

        # Base score calculation
        unvisited = max(1, btotal - bcovered_cur + 1)
        visited = bcovered_cur - bcovered_pre + 1

        # Apply logarithmic scaling
        return math.log(visited + 1) * math.log(unvisited + 1)

    def penalized_score(self, node_data, graph=None, node=None, penalty_factor=0.9):
        """Apply a penalty for repeatedly failing to visit a node."""
        bcovered_cur = node_data.get('bcovered_cur', 0)
        bcovered_pre = node_data.get('bcovered_pre', 0)
        btotal = node_data.get('btotal', 0)
        attempts = node_data.get('attempts', 0) 

        # Base score calculation
        unvisited_score = (btotal - bcovered_cur + 1)
        visited_contribution = (bcovered_cur - bcovered_pre + 1)

        # Apply penalty for repeated failures
        penalty = penalty_factor ** attempts

        return round(penalty * visited_contribution * unvisited_score, 3)

    def penalized_degree_score(self, node_data, graph=None, node=None, penalty_factor=0.9):
        """Apply a penalty for repeatedly failing to visit a node."""
        bcovered_cur = node_data.get('bcovered_cur', 0)
        bcovered_pre = node_data.get('bcovered_pre', 0)
        btotal = node_data.get('btotal', 0)
        attempts = node_data.get('attempts', 0) 

        # Base score calculation
        unvisited_score = math.log(btotal - bcovered_cur + math.e)
        diff = bcovered_cur - bcovered_pre
        if diff < 0:
            logging.warning(f"[penalized_degree_score] Negative diff at node {node}: bcovered_cur={bcovered_cur}, bcovered_pre={bcovered_pre}. Setting diff=0.")
            diff = 0
        visited_contribution = math.log(diff + math.e)

        # Apply penalty for repeated failures
        penalty = penalty_factor ** attempts

        degree = graph.out_degree(node) + graph.in_degree(node)

        return round(penalty * visited_contribution * (visited_contribution + degree), 3)

    def penalized_degree_centrality_score(self, node_data, graph=None, node=None, penalty_factor=0.8):
        """Apply penalty using Degree Centrality or Katz Centrality."""

        bcovered_cur = node_data.get('bcovered_cur', 0)
        bcovered_pre = node_data.get('bcovered_pre', 0)
        btotal = node_data.get('btotal', 0)
        attempts = node_data.get('attempts', 0)

        # if btotal == 0:
        #     return 0.0  # Avoid zero division

        # Features
        unvisited = max(btotal - bcovered_cur, 1)
        recent_gain = max(bcovered_cur - bcovered_pre, 1)
        normalized_attempts = math.tanh(attempts / 5.0)
        penalty = 1.0 - normalized_attempts

        # Centrality
        if self.use_katz:
            centrality = self.katz_scores.get(node, 0.0001)
        else:
            centrality = self.degree_centrality.get(node, 0.0001)
 
        # Scale centrality impact
        centrality_factor = math.tanh(centrality * 5.0)

        # Log-scaling to soften extreme large values
        score = (
            unvisited * recent_gain * penalty * centrality_factor
        )

        # logging.debug(f"Node: {node}, Unvisited: {unvisited}, Recent Gain: {recent_gain}, penalty: {penalty}, original centrality: {centrality}, Centrality: {centrality_factor}, final: {score}")

        return round(score, 5)

    def penalized_degree_pagerank_score(self, node_data, graph, node, pagerank_scores, penalty_factor=0.9):
        """Calculate a fuzzing score by combining PageRank, function coverage, and function size."""
        
        bcovered_cur = node_data.get('bcovered_cur', 0)
        bcovered_pre = node_data.get('bcovered_pre', 0)
        btotal = node_data.get('btotal', 0)
        attempts = node_data.get('attempts', 0)

        # Get PageRank score for this function
        pr_score = pagerank_scores.get(node, 0.0001)  # Avoid zero division

        # Growth Ratio (coverage improvement factor)
        growth_ratio = (bcovered_cur - bcovered_pre + 1) / (btotal + 1)
        growth_boost = 1 + ((btotal - bcovered_cur) / (btotal + 1)) * 2 # Boost for unvisited functions

        # Adaptive penalty factor (punishes stagnation, rewards progress)
        penalty = penalty_factor ** attempts

        # Function size influence (logarithmic boost)
        function_size = max(1, btotal)  # Ensure nonzero
        size_factor = 1 + math.log(function_size + 1)  # Log scale to prevent excessive impact

        # Final Score: Mix of PageRank, Coverage Growth, Penalty, and Function Size
        final_score = pr_score * (1 + growth_ratio * growth_boost) * penalty * size_factor

        logging.debug(f"PR: {pr_score}, Growth: {1 + growth_ratio * growth_boost}, Penalty: {penalty}, Size: {size_factor} for {node}, final: {final_score}")

        return round(final_score, 5)

    def node_degree_score(self, node_data, graph, node):
        """Score based on node degree in the graph."""
        if graph is None or node is None:
            raise ValueError("Graph and node must be provided for node degree scoring.")

        # Degree-based score: out-degree + in-degree
        degree_score = graph.out_degree(node) + graph.in_degree(node)

        # Combine with basic block-based score
        bcovered_pre = node_data.get('bcovered_pre', 0)
        bcovered_cur = node_data.get('bcovered_cur', 0)
        btotal = node_data.get('btotal', 0)
        block_score = (bcovered_cur - bcovered_pre + 1) * (btotal - bcovered_cur + 1)

        # Weighted combination of block and degree scores
        return 0.7 * block_score + 0.3 * degree_score

    def normalize_pagerank_scores(self, min_value=1, max_value=5):
        """Normalize PageRank scores to be between min_value and max_value."""
        if not self.pagerank_scores:
            return

        min_pr = min(self.pagerank_scores.values())
        max_pr = max(self.pagerank_scores.values())

        for node in self.pagerank_scores:
            if max_pr > min_pr:  # Avoid division by zero
                self.pagerank_scores[node] = min_value + ((self.pagerank_scores[node] - min_pr) / (max_pr - min_pr)) * (max_value - min_value)

    def normalize_centrality_scores(self, centrality, min_value=1, max_value=2):
        """Normalize Centrality scores to be between min_value and max_value."""
        min_pr = min(centrality.values())
        max_pr = max(centrality.values())

        for node in centrality:
            if max_pr > min_pr:  # Avoid division by zero
                centrality[node] = min_value + ((centrality[node] - min_pr) / (max_pr - min_pr)) * (max_value - min_value)

    def entropy_weighted_score(self, node_data, graph=None, node=None):
        if not hasattr(self, "_entropy_scores"):
            self._compute_entropy_scores()
        return self._entropy_scores.get(node, 0.0)

    def _compute_entropy_scores(self):
        node_list = list(self.graph.nodes)
        metric_vectors = []

        for node in node_list:
            data = self.graph.nodes[node]
            bcovered_cur = data.get('bcovered_cur', 0)
            bcovered_pre = data.get('bcovered_pre', 0)
            btotal = data.get('btotal', 0)
            attempts = data.get('attempts', 0)

            if btotal == 0:
                # Likely uninformed or external node (e.g., calloc): use only centrality
                unvisited = 0
                recent_gain = 0
                penalty = 0.1  # Small fixed value to avoid zeroing out
            else:
                unvisited = max(btotal - bcovered_cur, 1)
                recent_gain = max(bcovered_cur - bcovered_pre, 1)
                penalty = math.exp(-0.3 * attempts)

            centrality_raw = self.katz_scores.get(node, 0.0001) if self.use_katz \
                            else self.degree_centrality.get(node, 0.0001)

            metric_vectors.append([unvisited, recent_gain, penalty, centrality_raw])

        X = np.array(metric_vectors)
        norm = MinMaxScaler().fit_transform(X)
        eps = 1e-12
        prob = norm / (np.sum(norm, axis=0) + eps)
        entropy = -np.sum(prob * np.log(prob + eps), axis=0)
        max_entropy = np.log(len(node_list))
        info_gain = 1 - entropy / (max_entropy + eps)
        weights = info_gain / (np.sum(info_gain) + eps)

        scores = norm.dot(weights) * 100

        MAX_UNINFORMED_SCORE = 10.0
        UNINFORMED_SCALE = 0.5
        self._entropy_scores = {}
        for i, node in enumerate(node_list):
            data = self.graph.nodes[node]
            btotal = data.get('btotal', 0)
            score = round(scores[i], 5)
            if btotal == 0:
                # Cap score for nodes with no coverage info
                score = min(score * UNINFORMED_SCALE, MAX_UNINFORMED_SCORE)
            self._entropy_scores[node] = score

        # logging.info(f"[EntropyWeight] Weights: {weights}, Score sum: {sum(scores):.3f}")
