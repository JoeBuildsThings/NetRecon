(() => {
  "use strict";

  const DEG = Math.PI / 180;
  const TWO_PI = Math.PI * 2;

  // Simplified vector landmass outlines [lon, lat] for crisp 3D orthographic rendering
  const LANDMASSES = [
    // North America
    [
      [-166, 65], [-161, 59], [-152, 60], [-141, 60], [-131, 54], [-125, 49],
      [-124, 42], [-121, 35], [-117, 32], [-110, 24], [-105, 20], [-97, 16],
      [-88, 13], [-83, 9], [-78, 8], [-82, 14], [-87, 21], [-90, 21], [-97, 22],
      [-97, 27], [-90, 29], [-83, 29], [-81, 25], [-80, 31], [-75, 35], [-74, 40],
      [-70, 42], [-66, 45], [-60, 46], [-53, 47], [-56, 52], [-64, 58], [-78, 62],
      [-82, 55], [-92, 57], [-95, 64], [-110, 68], [-128, 70], [-142, 70], [-156, 71],
      [-166, 68]
    ],
    // Greenland
    [
      [-51, 60], [-42, 60], [-34, 67], [-20, 72], [-18, 80], [-36, 83],
      [-55, 81], [-68, 76], [-56, 68]
    ],
    // South America
    [
      [-78, 9], [-72, 11], [-62, 10], [-51, 2], [-44, -3], [-35, -6],
      [-38, -14], [-41, -22], [-48, -26], [-53, -34], [-58, -38], [-65, -42],
      [-68, -52], [-72, -55], [-75, -48], [-73, -38], [-71, -24], [-76, -15],
      [-81, -5], [-79, 2]
    ],
    // Europe
    [
      [-9, 37], [-9, 43], [-2, 43], [-5, 48], [2, 51], [8, 54], [10, 57],
      [14, 54], [20, 55], [24, 59], [28, 60], [22, 65], [30, 70], [42, 67],
      [58, 68], [60, 58], [48, 46], [38, 45], [29, 41], [23, 37], [19, 40],
      [14, 45], [16, 40], [12, 42], [6, 43], [0, 39], [-5, 36]
    ],
    // UK and Ireland
    [
      [-6, 50], [-2, 51], [2, 52], [-1, 55], [-3, 58], [-6, 57], [-5, 53]
    ],
    // Scandinavia
    [
      [5, 59], [10, 59], [12, 56], [18, 59], [21, 64], [26, 70], [18, 69],
      [11, 64], [5, 61]
    ],
    // Africa
    [
      [-17, 15], [-13, 27], [-6, 35], [10, 37], [15, 32], [25, 32], [32, 31],
      [39, 21], [43, 12], [51, 12], [47, 4], [41, -2], [40, -11], [35, -20],
      [32, -26], [28, -33], [19, -35], [15, -26], [12, -16], [12, -6], [9, 4],
      [2, 6], [-8, 5], [-15, 11]
    ],
    // Madagascar
    [
      [44, -25], [47, -25], [50, -15], [49, -12], [45, -18]
    ],
    // Asia and Middle East
    [
      [29, 41], [36, 37], [35, 31], [43, 13], [54, 17], [59, 22], [50, 28],
      [56, 26], [62, 25], [68, 24], [73, 18], [77, 8], [82, 16], [89, 22],
      [96, 17], [100, 12], [103, 2], [104, 10], [109, 13], [108, 21], [116, 23],
      [121, 29], [122, 37], [128, 35], [130, 42], [136, 45], [141, 53], [150, 59],
      [161, 60], [174, 65], [178, 68], [160, 70], [136, 72], [114, 74], [95, 76],
      [75, 72], [60, 69], [58, 58], [48, 46], [39, 44]
    ],
    // Japan
    [
      [130, 31], [134, 34], [140, 36], [141, 41], [145, 44], [141, 44],
      [137, 37], [131, 34]
    ],
    // Indonesia (Sumatra / Java / Borneo)
    [
      [96, 5], [101, 1], [106, -6], [114, -8], [111, -7], [103, -2], [97, 2]
    ],
    [
      [109, 1], [115, 5], [119, 1], [116, -3], [111, -3]
    ],
    // Australia
    [
      [114, -22], [122, -18], [130, -12], [136, -12], [142, -11], [146, -18],
      [153, -26], [151, -34], [147, -38], [139, -36], [131, -32], [122, -34],
      [115, -34], [113, -26]
    ],
    // New Zealand
    [
      [167, -46], [172, -43], [175, -38], [178, -37], [175, -41], [169, -46]
    ]
  ];

  // Passive backbone telemetry reference hubs for ambient situational context
  const REFERENCE_HUBS = [
    { name: "Ashburn", lat: 39.04, lon: -77.49 },
    { name: "Frankfurt", lat: 50.11, lon: 8.68 },
    { name: "London", lat: 51.51, lon: -0.13 },
    { name: "Lagos", lat: 6.52, lon: 3.38 },
    { name: "Singapore", lat: 1.35, lon: 103.82 },
    { name: "Tokyo", lat: 35.68, lon: 139.65 },
    { name: "Sao Paulo", lat: -23.55, lon: -46.63 },
    { name: "Sydney", lat: -33.87, lon: 151.21 }
  ];

  function project(latDeg, lonDeg, rotLon, rotLat, radius, cx, cy) {
    const phi = latDeg * DEG;
    const lambda = lonDeg * DEG - rotLon;
    const cosPhi = Math.cos(phi);
    const sinPhi = Math.sin(phi);
    const cosLam = Math.cos(lambda);
    const sinLam = Math.sin(lambda);
    const cosRotLat = Math.cos(rotLat);
    const sinRotLat = Math.sin(rotLat);

    const x = cosPhi * sinLam;
    const y = sinPhi * cosRotLat - cosPhi * cosLam * sinRotLat;
    const z = sinPhi * sinRotLat + cosPhi * cosLam * cosRotLat;

    return {
      x: cx + x * radius,
      y: cy - y * radius,
      z: z,
      visible: z >= 0
    };
  }

  function interpolateArc(a, b, steps) {
    const lat1 = a.lat * DEG;
    const lon1 = a.lon * DEG;
    const lat2 = b.lat * DEG;
    const lon2 = b.lon * DEG;

    const x1 = Math.cos(lat1) * Math.cos(lon1);
    const y1 = Math.cos(lat1) * Math.sin(lon1);
    const z1 = Math.sin(lat1);

    const x2 = Math.cos(lat2) * Math.cos(lon2);
    const y2 = Math.cos(lat2) * Math.sin(lon2);
    const z2 = Math.sin(lat2);

    const dot = Math.max(-1, Math.min(1, x1 * x2 + y1 * y2 + z1 * z2));
    const omega = Math.acos(dot);
    const points = [];

    for (let i = 0; i <= steps; i++) {
      const t = i / steps;
      let x, y, z;
      if (omega < 0.001) {
        x = x1 + (x2 - x1) * t;
        y = y1 + (y2 - y1) * t;
        z = z1 + (z2 - z1) * t;
      } else {
        const sinO = Math.sin(omega);
        const w1 = Math.sin((1 - t) * omega) / sinO;
        const w2 = Math.sin(t * omega) / sinO;
        x = w1 * x1 + w2 * x2;
        y = w1 * y1 + w2 * y2;
        z = w1 * z1 + w2 * z2;
      }
      const norm = Math.hypot(x, y, z) || 1;
      const lat = Math.asin(z / norm) / DEG;
      const lon = Math.atan2(y / norm, x / norm) / DEG;
      const lift = 1 + Math.sin(t * Math.PI) * 0.14;
      points.push({ lat, lon, lift });
    }
    return points;
  }

  function normalizeAngle(rad) {
    let a = rad % TWO_PI;
    if (a > Math.PI) a -= TWO_PI;
    if (a < -Math.PI) a += TWO_PI;
    return a;
  }

  function createGlobe(canvas) {
    const ctx = canvas.getContext("2d");
    const reducedMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    let width = 400;
    let height = 340;
    let dpr = Math.min(window.devicePixelRatio || 1, 2);

    let rotLon = 10 * DEG;
    let rotLat = 16 * DEG;
    let targetRotLon = null;
    let targetRotLat = null;
    let zoom = 1.0;
    let isPaused = Boolean(reducedMotion);
    let isDragging = false;
    let dragX = 0;
    let dragY = 0;
    let animFrame = null;
    let pulsePhase = 0;
    let arcProgress = 0;

    let activeTarget = null;
    let originNode = { lat: 6.52, lon: 3.38, name: "Origin" };
    let activeArc = [];
    let trackedHistory = [];

    function resize() {
      const rect = canvas.getBoundingClientRect();
      width = Math.max(240, Math.round(rect.width || 400));
      height = Math.max(220, Math.round(rect.height || 340));
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      canvas.width = Math.round(width * dpr);
      canvas.height = Math.round(height * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      draw();
    }

    function drawGraticule(radius, cx, cy) {
      ctx.save();
      ctx.lineWidth = 0.75;

      // Latitude rings
      for (let lat = -60; lat <= 60; lat += 30) {
        ctx.beginPath();
        let penDown = false;
        for (let lon = -180; lon <= 180; lon += 6) {
          const p = project(lat, lon, rotLon, rotLat, radius, cx, cy);
          if (p.visible) {
            if (!penDown) {
              ctx.moveTo(p.x, p.y);
              penDown = true;
            } else {
              ctx.lineTo(p.x, p.y);
            }
          } else {
            penDown = false;
          }
        }
        ctx.strokeStyle = lat === 0 ? "rgba(57, 255, 136, 0.20)" : "rgba(128, 173, 148, 0.12)";
        ctx.stroke();
      }

      // Longitude meridians
      for (let lon = -180; lon < 180; lon += 30) {
        ctx.beginPath();
        let penDown = false;
        for (let lat = -84; lat <= 84; lat += 6) {
          const p = project(lat, lon, rotLon, rotLat, radius, cx, cy);
          if (p.visible) {
            if (!penDown) {
              ctx.moveTo(p.x, p.y);
              penDown = true;
            } else {
              ctx.lineTo(p.x, p.y);
            }
          } else {
            penDown = false;
          }
        }
        ctx.strokeStyle = lon === 0 ? "rgba(57, 255, 136, 0.18)" : "rgba(128, 173, 148, 0.11)";
        ctx.stroke();
      }
      ctx.restore();
    }

    function drawLandmasses(radius, cx, cy) {
      ctx.save();
      ctx.beginPath();
      ctx.arc(cx, cy, radius, 0, TWO_PI);
      ctx.clip();

      LANDMASSES.forEach((poly) => {
        const projected = poly.map(([lon, lat]) => project(lat, lon, rotLon, rotLat, radius, cx, cy));
        let anyVisible = false;
        for (let i = 0; i < projected.length; i++) {
          if (projected[i].z > -0.15) {
            anyVisible = true;
            break;
          }
        }
        if (!anyVisible) return;

        // Fill landmass hemisphere segment
        ctx.beginPath();
        let started = false;
        for (let i = 0; i < projected.length; i++) {
          const pt = projected[i];
          if (pt.z >= -0.04) {
            if (!started) {
              ctx.moveTo(pt.x, pt.y);
              started = true;
            } else {
              ctx.lineTo(pt.x, pt.y);
            }
          } else {
            started = false;
          }
        }
        ctx.fillStyle = "rgba(25, 62, 43, 0.42)";
        ctx.fill();

        // Crisp tactical coastline stroke
        ctx.beginPath();
        let penDown = false;
        for (let i = 0; i <= projected.length; i++) {
          const pt = projected[i % projected.length];
          if (pt.visible) {
            if (!penDown) {
              ctx.moveTo(pt.x, pt.y);
              penDown = true;
            } else {
              ctx.lineTo(pt.x, pt.y);
            }
          } else {
            penDown = false;
          }
        }
        ctx.strokeStyle = "rgba(82, 214, 138, 0.58)";
        ctx.lineWidth = 1.15;
        ctx.stroke();
      });

      ctx.restore();
    }

    function drawReferenceHubs(radius, cx, cy) {
      REFERENCE_HUBS.forEach((hub) => {
        const p = project(hub.lat, hub.lon, rotLon, rotLat, radius, cx, cy);
        if (!p.visible) return;
        const alpha = 0.25 + p.z * 0.45;
        ctx.beginPath();
        ctx.arc(p.x, p.y, 2, 0, TWO_PI);
        ctx.fillStyle = `rgba(143, 189, 162, ${alpha.toFixed(2)})`;
        ctx.fill();
      });

      trackedHistory.forEach((node) => {
        if (activeTarget && node.lat === activeTarget.lat && node.lon === activeTarget.lon) return;
        const p = project(node.lat, node.lon, rotLon, rotLat, radius, cx, cy);
        if (!p.visible) return;
        ctx.beginPath();
        ctx.arc(p.x, p.y, 3, 0, TWO_PI);
        ctx.fillStyle = "rgba(245, 184, 65, 0.78)";
        ctx.fill();
      });
    }

    function drawTrackingArc(radius, cx, cy) {
      if (!activeArc.length) return;
      ctx.save();
      ctx.beginPath();
      let penDown = false;
      const limit = Math.max(2, Math.floor(activeArc.length * Math.min(1, arcProgress)));

      for (let i = 0; i < limit; i++) {
        const node = activeArc[i];
        const p = project(node.lat, node.lon, rotLon, rotLat, radius * node.lift, cx, cy);
        if (p.z > -0.1) {
          if (!penDown) {
            ctx.moveTo(p.x, p.y);
            penDown = true;
          } else {
            ctx.lineTo(p.x, p.y);
          }
        } else {
          penDown = false;
        }
      }
      ctx.strokeStyle = "rgba(57, 255, 136, 0.78)";
      ctx.lineWidth = 1.8;
      ctx.setLineDash([4, 3]);
      ctx.stroke();
      ctx.setLineDash([]);

      // Moving packet indicator along the arc
      const packetIdx = Math.floor(((pulsePhase * 0.45) % 1) * (activeArc.length - 1));
      const packetNode = activeArc[packetIdx];
      if (packetNode) {
        const pp = project(packetNode.lat, packetNode.lon, rotLon, rotLat, radius * packetNode.lift, cx, cy);
        if (pp.visible) {
          ctx.beginPath();
          ctx.arc(pp.x, pp.y, 3.2, 0, TWO_PI);
          ctx.fillStyle = "#eef5f0";
          ctx.fill();
        }
      }
      ctx.restore();
    }

    function drawTargetReticle(radius, cx, cy) {
      if (!activeTarget) return;
      const p = project(activeTarget.lat, activeTarget.lon, rotLon, rotLat, radius, cx, cy);
      if (!p.visible) return;

      const ringPulse = (pulsePhase % 1);
      const outerR = 8 + ringPulse * 18;
      const outerAlpha = Math.max(0, 0.75 * (1 - ringPulse));

      ctx.save();

      // Expanding ping ring
      ctx.beginPath();
      ctx.arc(p.x, p.y, outerR, 0, TWO_PI);
      ctx.strokeStyle = `rgba(57, 255, 136, ${outerAlpha.toFixed(2)})`;
      ctx.lineWidth = 1.4;
      ctx.stroke();

      // Tactical crosshair ticks
      ctx.strokeStyle = "rgba(57, 255, 136, 0.9)";
      ctx.lineWidth = 1.25;
      const tickIn = 7;
      const tickOut = 13;
      ctx.beginPath();
      ctx.moveTo(p.x - tickOut, p.y);
      ctx.lineTo(p.x - tickIn, p.y);
      ctx.moveTo(p.x + tickIn, p.y);
      ctx.lineTo(p.x + tickOut, p.y);
      ctx.moveTo(p.x, p.y - tickOut);
      ctx.lineTo(p.x, p.y - tickIn);
      ctx.moveTo(p.x, p.y + tickIn);
      ctx.lineTo(p.x, p.y + tickOut);
      ctx.stroke();

      // Core beacon
      ctx.beginPath();
      ctx.arc(p.x, p.y, 4.2, 0, TWO_PI);
      ctx.fillStyle = "#39ff88";
      ctx.fill();
      ctx.lineWidth = 1.5;
      ctx.strokeStyle = "#06110a";
      ctx.stroke();

      // Callout label
      if (activeTarget.label) {
        const tag = activeTarget.label.slice(0, 26);
        ctx.font = "600 11px ui-monospace, SFMono-Regular, Menlo, monospace";
        const tw = ctx.measureText(tag).width;
        const boxW = tw + 14;
        const boxH = 22;
        const flipLeft = p.x + boxW + 20 > width;
        const bx = flipLeft ? p.x - boxW - 14 : p.x + 14;
        const by = Math.max(10, Math.min(height - boxH - 10, p.y - 11));

        ctx.fillStyle = "rgba(7, 12, 9, 0.92)";
        ctx.strokeStyle = "rgba(57, 255, 136, 0.55)";
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.rect(bx, by, boxW, boxH);
        ctx.fill();
        ctx.stroke();

        ctx.fillStyle = "#eef5f0";
        ctx.fillText(tag, bx + 7, by + 15);
      }

      ctx.restore();
    }

    function draw() {
      ctx.clearRect(0, 0, width, height);
      const cx = width / 2;
      const cy = height / 2;
      const baseRadius = Math.min(width, height) * 0.42;
      const radius = baseRadius * zoom;

      // Subtle atmospheric halo
      const halo = ctx.createRadialGradient(cx, cy, radius * 0.78, cx, cy, radius * 1.18);
      halo.addColorStop(0, "rgba(57, 255, 136, 0.06)");
      halo.addColorStop(0.7, "rgba(57, 255, 136, 0.03)");
      halo.addColorStop(1, "rgba(57, 255, 136, 0)");
      ctx.beginPath();
      ctx.arc(cx, cy, radius * 1.18, 0, TWO_PI);
      ctx.fillStyle = halo;
      ctx.fill();

      // Sphere body shading
      const sphereGrad = ctx.createRadialGradient(
        cx - radius * 0.32,
        cy - radius * 0.32,
        radius * 0.12,
        cx,
        cy,
        radius
      );
      sphereGrad.addColorStop(0, "#14241c");
      sphereGrad.addColorStop(0.65, "#0b1410");
      sphereGrad.addColorStop(1, "#060a08");

      ctx.beginPath();
      ctx.arc(cx, cy, radius, 0, TWO_PI);
      ctx.fillStyle = sphereGrad;
      ctx.fill();

      drawGraticule(radius, cx, cy);
      drawLandmasses(radius, cx, cy);
      drawReferenceHubs(radius, cx, cy);
      drawTrackingArc(radius, cx, cy);
      drawTargetReticle(radius, cx, cy);

      // Outer precision rim ring
      ctx.beginPath();
      ctx.arc(cx, cy, radius, 0, TWO_PI);
      ctx.strokeStyle = activeTarget ? "rgba(57, 255, 136, 0.48)" : "rgba(116, 158, 135, 0.32)";
      ctx.lineWidth = 1.25;
      ctx.stroke();

      // Subtle outer compass tick ring
      ctx.save();
      ctx.strokeStyle = "rgba(128, 173, 148, 0.16)";
      ctx.lineWidth = 1;
      for (let i = 0; i < 36; i++) {
        const angle = (i * 10) * DEG;
        const inner = radius + 5;
        const outer = i % 3 === 0 ? radius + 11 : radius + 8;
        ctx.beginPath();
        ctx.moveTo(cx + Math.cos(angle) * inner, cy + Math.sin(angle) * inner);
        ctx.lineTo(cx + Math.cos(angle) * outer, cy + Math.sin(angle) * outer);
        ctx.stroke();
      }
      ctx.restore();
    }

    function step() {
      if (targetRotLon !== null && targetRotLat !== null) {
        const dLon = normalizeAngle(targetRotLon - rotLon);
        const dLat = targetRotLat - rotLat;
        rotLon = normalizeAngle(rotLon + dLon * 0.1);
        rotLat = Math.max(-1.25, Math.min(1.25, rotLat + dLat * 0.1));
        if (Math.abs(dLon) < 0.004 && Math.abs(dLat) < 0.004) {
          rotLon = targetRotLon;
          rotLat = targetRotLat;
          targetRotLon = null;
          targetRotLat = null;
        }
      } else if (!isPaused && !isDragging) {
        rotLon = normalizeAngle(rotLon + 0.0026);
      }

      if (!isPaused) {
        pulsePhase = (pulsePhase + 0.015) % 1000;
        if (activeArc.length && arcProgress < 1) {
          arcProgress = Math.min(1, arcProgress + 0.04);
        }
      } else if (activeArc.length) {
        arcProgress = 1;
      }

      draw();
      animFrame = window.requestAnimationFrame(step);
    }

    function onPointerDown(event) {
      isDragging = true;
      targetRotLon = null;
      targetRotLat = null;
      dragX = event.clientX;
      dragY = event.clientY;
      canvas.setPointerCapture(event.pointerId);
      canvas.style.cursor = "grabbing";
    }

    function onPointerMove(event) {
      if (!isDragging) return;
      const dx = event.clientX - dragX;
      const dy = event.clientY - dragY;
      dragX = event.clientX;
      dragY = event.clientY;
      rotLon = normalizeAngle(rotLon - dx * 0.0065);
      rotLat = Math.max(-1.25, Math.min(1.25, rotLat + dy * 0.0065));
      draw();
    }

    function onPointerUp(event) {
      if (!isDragging) return;
      isDragging = false;
      try {
        canvas.releasePointerCapture(event.pointerId);
      } catch (_err) {
        // Ignore release errors when pointer leaves viewport
      }
      canvas.style.cursor = "grab";
    }

    canvas.style.cursor = "grab";
    canvas.addEventListener("pointerdown", onPointerDown);
    canvas.addEventListener("pointermove", onPointerMove);
    canvas.addEventListener("pointerup", onPointerUp);
    canvas.addEventListener("pointercancel", onPointerUp);

    const resizeObserver = typeof ResizeObserver !== "undefined"
      ? new ResizeObserver(() => resize())
      : null;
    if (resizeObserver) {
      resizeObserver.observe(canvas);
    } else {
      window.addEventListener("resize", resize);
    }

    resize();
    animFrame = window.requestAnimationFrame(step);

    return {
      plotTarget(target) {
        if (!target || typeof target.lat !== "number" || typeof target.lon !== "number") {
          activeTarget = null;
          activeArc = [];
          draw();
          return;
        }
        const prev = activeTarget ? { lat: activeTarget.lat, lon: activeTarget.lon } : originNode;
        activeTarget = {
          lat: target.lat,
          lon: target.lon,
          label: target.label || ""
        };
        if (Math.abs(prev.lat - target.lat) > 0.5 || Math.abs(prev.lon - target.lon) > 0.5) {
          activeArc = interpolateArc(prev, activeTarget, 48);
          arcProgress = isPaused ? 1 : 0.05;
        } else {
          activeArc = [];
        }
        if (!trackedHistory.some((item) => item.lat === target.lat && item.lon === target.lon)) {
          trackedHistory.push({ lat: target.lat, lon: target.lon });
          if (trackedHistory.length > 8) trackedHistory.shift();
        }
        targetRotLon = normalizeAngle(target.lon * DEG);
        targetRotLat = Math.max(-1.15, Math.min(1.15, target.lat * DEG));
        draw();
      },
      clearTarget() {
        activeTarget = null;
        activeArc = [];
        draw();
      },
      togglePause() {
        isPaused = !isPaused;
        return isPaused;
      },
      isPaused() {
        return isPaused;
      },
      zoomIn() {
        zoom = Math.min(1.45, Number((zoom + 0.15).toFixed(2)));
        draw();
      },
      zoomOut() {
        zoom = Math.max(0.8, Number((zoom - 0.15).toFixed(2)));
        draw();
      },
      resetView() {
        zoom = 1.0;
        if (activeTarget) {
          targetRotLon = normalizeAngle(activeTarget.lon * DEG);
          targetRotLat = Math.max(-1.15, Math.min(1.15, activeTarget.lat * DEG));
        } else {
          targetRotLon = 10 * DEG;
          targetRotLat = 16 * DEG;
        }
        draw();
      },
      destroy() {
        if (animFrame) window.cancelAnimationFrame(animFrame);
        if (resizeObserver) resizeObserver.disconnect();
        canvas.removeEventListener("pointerdown", onPointerDown);
        canvas.removeEventListener("pointermove", onPointerMove);
        canvas.removeEventListener("pointerup", onPointerUp);
        canvas.removeEventListener("pointercancel", onPointerUp);
      }
    };
  }

  window.NetReconGlobe = { createGlobe };
})();
