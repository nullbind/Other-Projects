// Author Scott Sutherland
// Custom BlastZone Layout
(function() {
    'use strict';

    function BlastZoneLayout(options) {
        this.options = options;
    }

    BlastZoneLayout.prototype.run = function() {
        var cy = this.options.cy;
        var nodes = cy.nodes();
        var selectedNode = cy.getElementById(this.options.centerNode);

        if (!selectedNode || selectedNode.empty()) {
            console.error("Center node not found or not provided.");
            return;
        }

        var concentricDistances = {};

        nodes.forEach(function(node) {
            var dijkstra = cy.elements().dijkstra(selectedNode, function(edge) {
                return 1;
            });
            var distance = dijkstra.distanceTo(node);
            concentricDistances[node.id()] = distance;
        });

        var maxDistance = Math.max(...Object.values(concentricDistances));

        var centerX = cy.width() / 2;
        var centerY = cy.height() / 2;
        selectedNode.position({ x: centerX, y: centerY });

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

        cy.fit();
        cy.emit('layoutready');
        cy.emit('layoutstop');
    };

    cytoscape('layout', 'BlastZone', BlastZoneLayout);

})();
