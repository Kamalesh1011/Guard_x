import React, { useEffect, useRef, useState } from 'react'
import { api } from '../utils/api'

export default function ProcessTree() {
  const containerRef = useRef(null)
  const svgRef = useRef(null)
  const [data, setData] = useState({ nodes: [], edges: [] })
  const [selected, setSelected] = useState(null)
  const [dimensions, setDimensions] = useState({ width: 800, height: 600 })

  useEffect(() => {
    api.getProcesses().then(setData).catch(console.error)
    const interval = setInterval(() => {
      api.getProcesses().then(setData).catch(console.error)
    }, 5000)
    return () => clearInterval(interval)
  }, [])

  useEffect(() => {
    const container = containerRef.current
    if (!container) return

    const observer = new ResizeObserver((entries) => {
      for (const entry of entries) {
        const { width, height } = entry.contentRect
        if (width > 0 && height > 0) {
          setDimensions({ width, height })
        }
      }
    })
    observer.observe(container)
    return () => observer.disconnect()
  }, [])

  useEffect(() => {
    if (!data.nodes.length || !svgRef.current) return

    const { width, height } = dimensions
    if (width <= 0 || height <= 0) return

    import('d3').then((d3) => {
      const svg = d3.select(svgRef.current)
      svg.selectAll('*').remove()

      svg.attr('width', width).attr('height', height)

      const nodesSlice = data.nodes.slice(0, 80)
      const nodeIds = new Set(nodesSlice.map((n) => n.id))
      const edgesSlice = data.edges.filter(
        (e) => nodeIds.has(typeof e.source === 'object' ? e.source.id : e.source) &&
               nodeIds.has(typeof e.target === 'object' ? e.target.id : e.target)
      ).slice(0, 150)

      const simulation = d3
        .forceSimulation(nodesSlice)
        .force(
          'link',
          d3.forceLink(edgesSlice).id((d) => d.id).distance(40)
        )
        .force('charge', d3.forceManyBody().strength(-60))
        .force('center', d3.forceCenter(width / 2, height / 2))
        .force('collision', d3.forceCollide().radius(10))

      const link = svg
        .append('g')
        .selectAll('line')
        .data(edgesSlice)
        .join('line')
        .attr('stroke', '#374151')
        .attr('stroke-width', 0.5)
        .attr('stroke-opacity', 0.6)

      const node = svg
        .append('g')
        .selectAll('circle')
        .data(nodesSlice)
        .join('circle')
        .attr('r', (d) => Math.max(2, Math.min(6, (d.cpu || 0) / 15 + 2)))
        .attr('fill', (d) => {
          if ((d.cpu || 0) > 50) return '#ef4444'
          if ((d.cpu || 0) > 20) return '#eab308'
          return '#22c55e'
        })
        .attr('stroke', '#1f2937')
        .attr('stroke-width', 0.5)
        .attr('cursor', 'pointer')
        .on('click', (event, d) => {
          event.stopPropagation()
          setSelected(d)
        })

      node.append('title').text((d) => `${d.name}\nPID: ${d.id}\nCPU: ${(d.cpu || 0).toFixed(1)}%`)

      node.call(
        d3.drag()
          .on('start', (event, d) => {
            if (!event.active) simulation.alphaTarget(0.3).restart()
            d.fx = d.x
            d.fy = d.y
          })
          .on('drag', (event, d) => {
            d.fx = event.x
            d.fy = event.y
          })
          .on('end', (event, d) => {
            if (!event.active) simulation.alphaTarget(0)
            d.fx = null
            d.fy = null
          })
      )

      svg.on('click', () => setSelected(null))

      simulation.on('tick', () => {
        link
          .attr('x1', (d) => d.source.x)
          .attr('y1', (d) => d.source.y)
          .attr('x2', (d) => d.target.x)
          .attr('y2', (d) => d.target.y)

        node.attr('cx', (d) => d.x).attr('cy', (d) => d.y)
      })
    })
  }, [data, dimensions])

  return (
    <div className="p-6 h-full flex flex-col">
      <h1 className="text-2xl font-bold text-white mb-4">Process Tree</h1>
      <div
        ref={containerRef}
        className="flex-1 bg-gray-900 rounded-xl border border-gray-800 overflow-hidden relative"
        style={{ minHeight: '500px' }}
      >
        <svg ref={svgRef} />
        {selected && (
          <div className="absolute top-4 right-4 bg-gray-800 rounded-lg p-4 border border-gray-700 w-64 shadow-xl">
            <h3 className="text-white font-medium mb-2">{selected.name}</h3>
            <p className="text-gray-400 text-sm">PID: {selected.id}</p>
            <p className="text-gray-400 text-sm">CPU: {(selected.cpu || 0).toFixed(1)}%</p>
            <p className="text-gray-400 text-sm">Memory: {(selected.memory || 0).toFixed(1)}%</p>
            <button
              onClick={() => setSelected(null)}
              className="mt-3 px-2 py-1 bg-gray-700 hover:bg-gray-600 rounded text-xs text-gray-300"
            >
              Close
            </button>
          </div>
        )}
      </div>
    </div>
  )
}
