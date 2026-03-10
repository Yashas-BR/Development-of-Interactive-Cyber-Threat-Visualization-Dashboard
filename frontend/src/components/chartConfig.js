import Plot from 'react-plotly.js'

const COMMON_LAYOUT = {
  paper_bgcolor: 'transparent',
  plot_bgcolor: 'transparent',
  font: { family: 'Inter, sans-serif', color: '#6b8caa', size: 11 },
  margin: { t: 10, r: 10, b: 40, l: 40 },
  xaxis: {
    gridcolor: 'rgba(0,200,255,0.06)',
    tickcolor: 'rgba(0,200,255,0.2)',
    linecolor: 'rgba(0,200,255,0.08)',
    zerolinecolor: 'rgba(0,200,255,0.08)',
  },
  yaxis: {
    gridcolor: 'rgba(0,200,255,0.06)',
    tickcolor: 'rgba(0,200,255,0.2)',
    linecolor: 'rgba(0,200,255,0.08)',
    zerolinecolor: 'rgba(0,200,255,0.08)',
  },
}

const CONFIG = { displayModeBar: false, responsive: true }

export { COMMON_LAYOUT, CONFIG }
