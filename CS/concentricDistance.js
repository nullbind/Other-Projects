(function() {
  'use strict';

  // Define the layout
  function ConcentricDistanceLayout(options) {
    this.options = options;
  }

  // Add the `run` method to the layout prototype
  ConcentricDistanceLayout.prototype.run = function() {
    var cy = this.options.cy;
    var nodes = cy.nodes();
    var selectedNode = cy.getElementById(this.options.centerNode);

    if (!selectedNode || selectedNode.empty()) {
      console.error("Center node not found or not provided.");
      return;
    }

    var concentricDistances = {};

    // Calculate distances from the selected node
    nodes.forEach(function(node) {
      var dijkstra = cy.elements().dijkstra(selectedNode, function(edge) {
        return 1; // Treat all edges equally
      });
      var distance = dijkstra.distanceTo(node);
      concentricDistances[node.id()] = distance;
    });

    // Get the maximum distance
    var maxDistance = Math.max(...Object.values(concentricDistances));

    // Place the selected node at the center
    var centerX = cy.width() / 2;
    var centerY = cy.height() / 2;
    selectedNode.position({ x: centerX, y: centerY });

    // Arrange other nodes in concentric circles
    for (var i = 1; i <= maxDistance; i++) {
      var nodesAtDistance = nodes.filter(function(node) {
        return concentricDistances[node.id()] === i;
      });

      var angleStep = (2 * Math.PI) / nodesAtDistance.length;
      var radius = i * this.options.radiusStep;

      nodesAtDistance.forEach(function(node, index) {
        var angle = index * angleStep;
        var x = centerX + radius * Math.cos(angle);
        var y = centerY + radius * Math.sin(angle);
        node.position({ x: x, y: y });
      });
    }

    cy.fit();  // Fit the graph to the viewport

    // Trigger the layoutready and layoutstop events
    cy.emit('layoutready');
    cy.emit('layoutstop');
  };

  // Register the layout
  cytoscape('layout', 'concentricDistance', ConcentricDistanceLayout);

})();
