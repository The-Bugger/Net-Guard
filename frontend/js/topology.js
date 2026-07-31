/**
 * topology.js — Animated network topology panel (Canvas 2D).
 *
 * Star topology: gateway at centre, server nodes surrounding it, attacker at edge.
 * On `new_threat` SocketIO event: animates a red pulse dot from attacker → gateway.
 *
 * ponytail: static layout, no D3 or new dependency. Upgrade path: D3 force simulation.
 */

const NetworkTopology = (() => {
  const NODE_R = 22;          // node circle radius
  const PULSE_R = 7;          // travelling pulse dot radius
  const PULSE_SPEED = 0.018;  // fraction of edge length per frame (0→1 progress)
  const PULSE_FADE = 0.55;    // alpha of pulse dot

  // Node definitions — positions set in resize()
  const NODES = {
    gateway:  { label: 'Gateway',  color: '#00E5FF', x: 0, y: 0 },
    server1:  { label: 'Server 1', color: '#4ADE80', x: 0, y: 0 },
    server2:  { label: 'Server 2', color: '#4ADE80', x: 0, y: 0 },
    server3:  { label: 'Server 3', color: '#4ADE80', x: 0, y: 0 },
    server4:  { label: 'Server 4', color: '#4ADE80', x: 0, y: 0 },
    attacker: { label: 'Attacker', color: '#F87171', x: 0, y: 0 },
  };

  // Active pulses: [{progress: 0→1, alpha: 1→0}]
  const pulses = [];

  let canvas, ctx, rafId;

  function init() {
    canvas = document.getElementById('network-topology');
    if (!canvas) return;
    ctx = canvas.getContext('2d');
    resize();
    window.addEventListener('resize', resize);

    // Wire up SocketIO new_threat → trigger pulse
    // SocketManager is defined in socket.js (loaded before this file)
    if (typeof SocketManager !== 'undefined') {
      SocketManager.on('new_threat', () => triggerPulse());
    }

    draw();
  }

  function resize() {
    if (!canvas) return;
    const w = canvas.clientWidth  || 480;
    const h = canvas.clientHeight || 260;
    canvas.width  = w;
    canvas.height = h;
    _layout(w, h);
  }

  function _layout(w, h) {
    const cx = w / 2, cy = h / 2;
    NODES.gateway.x = cx;
    NODES.gateway.y = cy;

    // Four server nodes in a ring around the gateway
    const servers = ['server1', 'server2', 'server3', 'server4'];
    const ringR = Math.min(w, h) * 0.28;
    servers.forEach((id, i) => {
      const angle = (i / servers.length) * Math.PI * 2 - Math.PI / 4;
      NODES[id].x = cx + Math.cos(angle) * ringR;
      NODES[id].y = cy + Math.sin(angle) * ringR;
    });

    // Attacker — bottom-left edge
    NODES.attacker.x = NODE_R * 2 + 8;
    NODES.attacker.y = h - NODE_R * 2 - 8;
  }

  function triggerPulse() {
    pulses.push({ progress: 0, alpha: 1 });
  }

  function draw() {
    rafId = requestAnimationFrame(draw);
    if (!ctx) return;
    const w = canvas.width, h = canvas.height;
    ctx.clearRect(0, 0, w, h);

    _drawEdges();
    _drawNodes();
    _updateAndDrawPulses();
  }

  function _drawEdges() {
    ctx.strokeStyle = 'rgba(148,163,184,0.25)';
    ctx.lineWidth = 1.5;

    // Gateway → each server
    ['server1', 'server2', 'server3', 'server4'].forEach(id => {
      _line(NODES.gateway, NODES[id]);
    });

    // Attacker → gateway (highlighted edge)
    ctx.strokeStyle = 'rgba(248,113,113,0.35)';
    ctx.lineWidth = 1.5;
    _line(NODES.attacker, NODES.gateway);
  }

  function _line(a, b) {
    ctx.beginPath();
    ctx.moveTo(a.x, a.y);
    ctx.lineTo(b.x, b.y);
    ctx.stroke();
  }

  function _drawNodes() {
    Object.values(NODES).forEach(n => {
      // Glow ring
      const grad = ctx.createRadialGradient(n.x, n.y, NODE_R * 0.5, n.x, n.y, NODE_R * 1.5);
      grad.addColorStop(0, n.color + '33');
      grad.addColorStop(1, 'transparent');
      ctx.beginPath();
      ctx.arc(n.x, n.y, NODE_R * 1.5, 0, Math.PI * 2);
      ctx.fillStyle = grad;
      ctx.fill();

      // Node circle
      ctx.beginPath();
      ctx.arc(n.x, n.y, NODE_R, 0, Math.PI * 2);
      ctx.fillStyle = '#1E293B';
      ctx.fill();
      ctx.strokeStyle = n.color;
      ctx.lineWidth = 2;
      ctx.stroke();

      // Label
      ctx.fillStyle = n.color;
      ctx.font = '11px Inter, Arial, sans-serif';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText(n.label, n.x, n.y);
    });
  }

  function _updateAndDrawPulses() {
    for (let i = pulses.length - 1; i >= 0; i--) {
      const p = pulses[i];
      p.progress += PULSE_SPEED;

      // Interpolate position along attacker→gateway edge
      const ax = NODES.attacker.x, ay = NODES.attacker.y;
      const gx = NODES.gateway.x,  gy = NODES.gateway.y;
      const x = ax + (gx - ax) * p.progress;
      const y = ay + (gy - ay) * p.progress;

      // Fade out in final 30% of travel
      p.alpha = p.progress > 0.7 ? (1 - p.progress) / 0.3 : 1;

      ctx.beginPath();
      ctx.arc(x, y, PULSE_R, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(248,113,113,${(p.alpha * PULSE_FADE).toFixed(3)})`;
      ctx.fill();

      // Trailing glow
      const g = ctx.createRadialGradient(x, y, 1, x, y, PULSE_R * 2.5);
      g.addColorStop(0, `rgba(248,113,113,${(p.alpha * 0.35).toFixed(3)})`);
      g.addColorStop(1, 'transparent');
      ctx.beginPath();
      ctx.arc(x, y, PULSE_R * 2.5, 0, Math.PI * 2);
      ctx.fillStyle = g;
      ctx.fill();

      if (p.progress >= 1) pulses.splice(i, 1);
    }
  }

  // Self-init on DOMContentLoaded
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  return { triggerPulse };  // expose for manual testing in console
})();
