#!/usr/bin/env python3
#
# btrpa-scan - Bluetooth Low Energy (BLE) Scanner with RPA Resolution
#
# Written by: David Kennedy (@HackingDave)
# Company:    TrustedSec
# Website:    https://www.trustedsec.com
#
# A BLE scanner that discovers broadcasting devices, searches for specific
# targets by MAC address, and resolves Resolvable Private Addresses (RPAs)
# using Identity Resolving Keys (IRKs) per the Bluetooth Core Specification.
#

"""Bluetooth LE scanner - scan all devices or search for a specific one."""

import argparse
import asyncio
import csv
import json
import os
import platform
import re
import signal
import socket
import webbrowser
import sys
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set

try:
    from bleak import BleakScanner
    from bleak.backends.device import BLEDevice
    from bleak.backends.scanner import AdvertisementData
except ImportError:
    print("Error: 'bleak' is not installed.")
    print("Install dependencies with:  pip install -r requirements.txt")
    sys.exit(1)

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    print("Error: 'cryptography' is not installed.")
    print("Install dependencies with:  pip install -r requirements.txt")
    sys.exit(1)

_HAS_CURSES = False
try:
    import curses
    _HAS_CURSES = True
except ImportError:
    pass

_HAS_FLASK = False
try:
    from flask import Flask, render_template_string, jsonify
    from flask_socketio import SocketIO
    _HAS_FLASK = True
except ImportError:
    pass

# Environment path loss exponents for distance estimation
_ENV_PATH_LOSS = {
    "free_space": 2.0,
    "outdoor": 2.2,
    "indoor": 3.0,
}

# Default reference-RSSI offset (dB) subtracted from TX Power to estimate
# the expected RSSI at the 1-metre reference distance.  The theoretical
# free-space path loss at 1 m for 2.4 GHz is ~41 dB, but real BLE devices
# add ~18 dB of antenna inefficiency, enclosure loss, and polarisation
# mismatch.  The iBeacon standard uses -59 dBm at 1 m for 0 dBm TX,
# which corresponds to an offset of 59.
_DEFAULT_REF_OFFSET = 59

# Polling / timing constants
_TUI_REFRESH_INTERVAL = 0.3       # seconds between TUI redraws
_SCAN_POLL_INTERVAL = 0.5         # seconds between poll cycles (continuous)
_TIMED_SCAN_POLL_INTERVAL = 0.1   # seconds between poll cycles (timed)
_GPS_RECONNECT_DELAY = 5          # seconds before GPS reconnect attempt
_GPS_SOCKET_TIMEOUT = 5           # seconds for GPS socket operations
_GPS_STARTUP_DELAY = 0.5          # seconds to wait for initial GPS connection

_FIELDNAMES = [
    "timestamp", "address", "name", "rssi", "avg_rssi", "tx_power",
    "est_distance", "latitude", "longitude", "gps_altitude",
    "manufacturer_data", "service_uuids", "resolved",
]

_BANNER = r"""
  _     _
 | |__ | |_ _ __ _ __   __ _       ___  ___ __ _ _ __
 | '_ \| __| '__| '_ \ / _` |_____/ __|/ __/ _` | '_ \
 | |_) | |_| |  | |_) | (_| |_____\__ \ (_| (_| | | | |
 |_.__/ \__|_|  | .__/ \__,_|     |___/\___\__,_|_| |_|
                |_|
   BLE Scanner with RPA Resolution
   by @HackingDave | TrustedSec
"""

_GUI_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>BTRPA-SCAN</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0a0a0a;--card:#1a1a1a;--border:#333;--text:#e0e0e0;
  --green:#00ff41;--cyan:#00e5ff;--yellow:#ffff00;--red:#ff4444;--dim:#666;
}
html,body{height:100%;background:var(--bg);color:var(--text);
  font-family:'Fira Code',Consolas,'Courier New',monospace;font-size:13px;
  overflow-x:hidden;position:relative}

/* ── matrix data rain background ─────────────────────────── */
#matrix-bg{position:fixed;inset:0;z-index:0;pointer-events:none;overflow:hidden}
#matrix-bg canvas{width:100%;height:100%}
/* everything else above the rain */
#header,#panels,#table-wrap,#tooltip,#overlay{position:relative;z-index:1}
a{color:var(--cyan)}

/* ── header bar ────────────────────────────────────────────── */
#header{display:flex;align-items:center;gap:18px;padding:8px 16px;
  background:#111;border-bottom:1px solid var(--border);flex-wrap:wrap}
#header .title{color:var(--green);font-weight:700;font-size:16px;letter-spacing:1px}
#header .stat{color:var(--text);font-size:12px}
#header .stat b{color:var(--green)}
#header .meta{font-size:11px;color:var(--dim);width:100%}

/* ── main panels ───────────────────────────────────────────── */
#panels{display:flex;height:calc(55vh - 50px);min-height:300px;
  border-bottom:1px solid var(--border)}
#radar-wrap{flex:3;position:relative;background:var(--card);
  border-right:1px solid var(--border);min-width:0}
#radar-canvas{width:100%;height:100%;display:block}
#map-wrap{flex:2;position:relative;min-width:0}
#map-wrap.hidden{display:none}
#radar-wrap.full{flex:1}
#map{width:100%;height:100%}

/* ── device table ──────────────────────────────────────────── */
#table-wrap{flex:1;overflow:auto;background:var(--bg);padding:4px 0}
#dev-table{width:100%;border-collapse:collapse}
#dev-table th{position:sticky;top:0;background:#111;color:var(--green);
  padding:6px 10px;text-align:left;cursor:pointer;user-select:none;
  border-bottom:1px solid var(--border);font-size:11px;white-space:nowrap}
#dev-table th:hover{color:var(--cyan)}
#dev-table td{padding:5px 10px;border-bottom:1px solid #1e1e1e;
  white-space:nowrap;font-size:12px}
#dev-table tr:hover td{background:#222}
#dev-table tr.highlight td{background:#1a2a1a}

/* ── tooltip ───────────────────────────────────────────────── */
#tooltip{position:fixed;pointer-events:none;background:rgba(10,10,10,.94);
  border:1px solid var(--green);border-radius:4px;padding:10px 14px;
  font-size:11px;line-height:1.6;max-width:380px;z-index:9999;display:none;
  box-shadow:0 4px 20px rgba(0,255,65,.12)}
#tooltip .lbl{color:var(--dim)}
#tooltip .val{color:var(--text)}

/* ── scan-complete overlay ─────────────────────────────────── */
#overlay{position:fixed;inset:0;background:rgba(0,0,0,.82);display:none;
  justify-content:center;align-items:center;z-index:10000;
  animation:fadeIn .6s ease}
#overlay .card{background:var(--card);border:1px solid var(--green);
  border-radius:8px;padding:36px 48px;text-align:center;
  box-shadow:0 0 40px rgba(0,255,65,.15)}
#overlay h2{color:var(--green);font-size:22px;margin-bottom:12px}
#overlay p{font-size:14px;margin:4px 0;color:var(--text)}
@keyframes fadeIn{from{opacity:0}to{opacity:1}}

/* leaflet popup override */
.leaflet-popup-content-wrapper{background:var(--card)!important;
  color:var(--text)!important;border-radius:4px!important;font-size:12px}
.leaflet-popup-tip{background:var(--card)!important}
</style>
</head>
<body>

<!-- matrix data rain background -->
<div id="matrix-bg"><canvas id="matrix-canvas"></canvas></div>

<!-- header -->
<div id="header">
  <span class="title">BTRPA-SCAN</span>
  <span class="stat" id="s-dot" style="color:var(--green)">&bull;</span>
  <span class="stat"><b id="s-unique">0</b> devices</span>
  <span class="stat"><b id="s-total">0</b> detections</span>
  <span class="stat"><b id="s-elapsed">00:00</b> elapsed</span>
  <div class="meta" id="s-meta"></div>
</div>

<!-- radar + map -->
<div id="panels">
  <div id="radar-wrap" class="full">
    <canvas id="radar-canvas"></canvas>
  </div>
  <div id="map-wrap" class="hidden">
    <div id="map"></div>
  </div>
</div>

<!-- device table -->
<div id="table-wrap">
<table id="dev-table">
  <thead><tr>
    <th data-col="address">Address</th>
    <th data-col="name">Name</th>
    <th data-col="rssi">RSSI</th>
    <th data-col="avg_rssi">Avg</th>
    <th data-col="est_distance">Distance</th>
    <th data-col="times_seen">Seen</th>
    <th data-col="last_seen">Last Seen</th>
  </tr></thead>
  <tbody id="dev-tbody"></tbody>
</table>
</div>

<!-- tooltip -->
<div id="tooltip"></div>

<!-- scan complete overlay -->
<div id="overlay">
  <div class="card">
    <h2>SCAN COMPLETE</h2>
    <p id="ov-elapsed"></p>
    <p id="ov-total"></p>
    <p id="ov-unique"></p>
  </div>
</div>

<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script src="/socket.io/socket.io.js"></script>
<!-- inject Jinja2 port variable before raw block -->
<script>var WSPORT = {{ port }};</script>
""" + r"""{% raw %}""" + r"""
<script>
(function(){
"use strict";

/* ================================================================
   State
   ================================================================ */
var devices = {};          // address -> device obj
var scannerGPS = null;     // {lat,lon,alt}
var hasGPS = false;
var sortCol = "rssi";
var sortAsc = false;
var hoveredAddr = null;

/* ================================================================
   Matrix Data Rain Background
   ================================================================ */
var mCanvas = document.getElementById("matrix-canvas");
var mCtx = mCanvas.getContext("2d");
var matrixCols = [];
var matrixData = []; // per-column: array of {char, alpha}
var MATRIX_FONT_SIZE = 13;
var matrixW = 0;

function resizeMatrix(){
  mCanvas.width  = window.innerWidth;
  mCanvas.height = window.innerHeight;
  matrixW = Math.floor(mCanvas.width / MATRIX_FONT_SIZE);
  // preserve existing columns, add new ones if wider
  while(matrixCols.length < matrixW) matrixCols.push(Math.random()*mCanvas.height);
  while(matrixData.length < matrixW) matrixData.push([]);
  matrixCols.length = matrixW;
  matrixData.length = matrixW;
}
window.addEventListener("resize", resizeMatrix);
resizeMatrix();

// pool of data strings to rain — updated with real device data
var matrixPool = [
  "FF:E1:A0:3B:9C:22","0x004C","RSSI:-45","2.4GHz","BLE5.0","SCAN","RPA",
  "0xFEED","AES128","IRK","GATT","L2CAP","ADV_IND","CONNECT",
  "CH37","CH38","CH39","iBeacon","UUID","GAP","SMP",
];

function feedMatrixPool(){
  if(matrixPool.length > 200) return; // cap pool size
  var addrs = Object.keys(devices);
  for(var i=0;i<addrs.length;i++){
    var d = devices[addrs[i]];
    if(matrixPool.indexOf(d.address)===-1) matrixPool.push(d.address);
    if(d.rssi!=null){
      var rStr = "RSSI:"+d.rssi;
      if(matrixPool.indexOf(rStr)===-1) matrixPool.push(rStr);
    }
    if(d.name && d.name!=="Unknown" && matrixPool.indexOf(d.name)===-1){
      matrixPool.push(d.name);
    }
    if(d.manufacturer_data && matrixPool.indexOf(d.manufacturer_data)===-1){
      matrixPool.push(d.manufacturer_data.substring(0,16));
    }
  }
}

function getMatrixChar(col){
  // pick a character from the pool or random hex
  if(Math.random()<0.3){
    var s = matrixPool[Math.floor(Math.random()*matrixPool.length)];
    var ci = Math.floor(Math.random()*s.length);
    return s[ci];
  }
  return "0123456789ABCDEF"[Math.floor(Math.random()*16)];
}

function drawMatrix(){
  // darken previous frame
  mCtx.fillStyle = "rgba(10,10,10,0.06)";
  mCtx.fillRect(0,0,mCanvas.width,mCanvas.height);
  mCtx.font = MATRIX_FONT_SIZE+"px monospace";
  for(var i=0;i<matrixW;i++){
    var x = i * MATRIX_FONT_SIZE;
    var y = matrixCols[i];
    var ch = getMatrixChar(i);
    // head character brighter
    mCtx.fillStyle = "rgba(0,255,65,0.25)";
    mCtx.fillText(ch, x, y);
    // trail character dimmer
    if(y > MATRIX_FONT_SIZE){
      mCtx.fillStyle = "rgba(0,255,65,0.06)";
      mCtx.fillText(ch, x, y - MATRIX_FONT_SIZE);
    }
    matrixCols[i] += MATRIX_FONT_SIZE;
    // reset column randomly or when off screen
    if(matrixCols[i] > mCanvas.height && Math.random()>0.975){
      matrixCols[i] = 0;
    }
  }
}
// update matrix pool every 5s with real device data
setInterval(feedMatrixPool, 5000);
// run matrix at ~20fps (independent of radar)
setInterval(drawMatrix, 50);

/* ================================================================
   Radar
   ================================================================ */
var rCanvas = document.getElementById("radar-canvas");
var rCtx    = rCanvas.getContext("2d");
var sweepAngle = 0;
var SWEEP_PERIOD = 4000; // ms per revolution
var RINGS = [1, 5, 10, 20]; // metres
var MAX_RING = 20;
var pingRipples = []; // {cx,cy,r,maxR,alpha,color,born}

function resizeCanvas(){
  var wrap = document.getElementById("radar-wrap");
  rCanvas.width  = wrap.clientWidth  * (window.devicePixelRatio||1);
  rCanvas.height = wrap.clientHeight * (window.devicePixelRatio||1);
  rCanvas.style.width  = wrap.clientWidth  + "px";
  rCanvas.style.height = wrap.clientHeight + "px";
}
window.addEventListener("resize", resizeCanvas);
resizeCanvas();

function hashAddr(addr){
  var h=0;
  for(var i=0;i<addr.length;i++){h=((h<<5)-h)+addr.charCodeAt(i);h|=0;}
  return Math.abs(h);
}

function distToRadius(d, maxR){
  if(d==null||d===""||d<=0) return maxR*0.85;
  var clamped = Math.min(d, MAX_RING);
  return (Math.log(clamped+1)/Math.log(MAX_RING+1))*maxR;
}

function dotColor(d){
  if(d==null||d===""||d<=0) return "#666666";
  if(d<5)  return "#00ff41";
  if(d<=15) return "#ffff00";
  return "#ff4444";
}

function hexToRgba(hex, a){
  var r=parseInt(hex.slice(1,3),16), g=parseInt(hex.slice(3,5),16), b=parseInt(hex.slice(5,7),16);
  return "rgba("+r+","+g+","+b+","+a+")";
}

/* ── ghost MAC flicker layer ────────────────────────────── */
// Ghosts: faint MAC addresses / data that materialize, flicker, and dissolve
// in the radar background. Each ghost has a lifecycle: fade in -> flicker -> fade out
var ghosts = []; // {text, x, y, born, lifespan, flickerRate, fontSize, angle}
var GHOST_MAX = 18;
var GHOST_SPAWN_INTERVAL = 400; // ms between spawns
var lastGhostSpawn = 0;

function spawnGhost(W, H, dpr){
  var addrs = Object.keys(devices);
  var text;
  if(addrs.length > 0 && Math.random() < 0.85){
    // mostly use real device data
    var dev = devices[addrs[Math.floor(Math.random()*addrs.length)]];
    var options = [dev.address];
    if(dev.name && dev.name !== "Unknown") options.push(dev.name);
    if(dev.rssi != null) options.push("RSSI:" + dev.rssi + "dBm");
    if(dev.manufacturer_data) options.push(dev.manufacturer_data.substring(0,20));
    if(dev.est_distance != null && dev.est_distance !== "") options.push("~" + Number(dev.est_distance).toFixed(1) + "m");
    if(dev.service_uuids) options.push(dev.service_uuids.substring(0,22));
    text = options[Math.floor(Math.random()*options.length)];
  } else {
    // filler hex strings and BLE terms
    var fillers = ["ADV_IND","SCAN_RSP","LL_DATA","ATT_MTU","SMP_PAIR",
      "0x"+Math.floor(Math.random()*0xFFFF).toString(16).toUpperCase().padStart(4,"0"),
      Math.floor(Math.random()*0xFFFFFF).toString(16).toUpperCase().padStart(6,"0")+":"+
      Math.floor(Math.random()*0xFFFFFF).toString(16).toUpperCase().padStart(6,"0")];
    text = fillers[Math.floor(Math.random()*fillers.length)];
  }
  // position: scattered across the full radar canvas, avoid dead center
  var x, y, attempts = 0;
  do {
    x = 40*dpr + Math.random()*(W - 80*dpr);
    y = 30*dpr + Math.random()*(H - 60*dpr);
    attempts++;
  } while(attempts < 5 && Math.abs(x-W/2)<60*dpr && Math.abs(y-H/2)<40*dpr);

  ghosts.push({
    text: text,
    x: x, y: y,
    born: Date.now(),
    lifespan: 2000 + Math.random()*3000, // 2-5 seconds
    flickerRate: 80 + Math.random()*200, // ms between flicker toggles
    fontSize: Math.floor(9 + Math.random()*3)*dpr, // 9-11px
    angle: (Math.random()-0.5)*0.12 // slight random tilt
  });
}

function drawGhosts(W, H, dpr){
  var now = Date.now();
  // spawn new ghosts
  if(now - lastGhostSpawn > GHOST_SPAWN_INTERVAL && ghosts.length < GHOST_MAX){
    spawnGhost(W, H, dpr);
    lastGhostSpawn = now;
  }
  // draw and cull
  for(var gi = ghosts.length-1; gi >= 0; gi--){
    var g = ghosts[gi];
    var age = now - g.born;
    if(age > g.lifespan){ ghosts.splice(gi,1); continue; }
    var progress = age / g.lifespan;
    // envelope: fade in (0-15%), sustain with flicker (15-80%), fade out (80-100%)
    var envelope;
    if(progress < 0.15) envelope = progress / 0.15;
    else if(progress > 0.80) envelope = (1 - progress) / 0.20;
    else envelope = 1;
    // flicker: random on/off toggling
    var flickerOn = Math.sin(age / g.flickerRate * Math.PI) > -0.3;
    if(!flickerOn && progress > 0.15 && progress < 0.80){
      // occasional hard flicker off
      if(Math.random() < 0.08) continue;
    }
    // occasional glitch: brief full-brightness flash
    var glitch = Math.random() < 0.006;
    var alpha = glitch ? 0.18 : Math.max(0, envelope * 0.09 * (flickerOn ? 1 : 0.2));
    if(alpha < 0.005) continue;

    rCtx.save();
    rCtx.translate(g.x, g.y);
    rCtx.rotate(g.angle);
    rCtx.font = g.fontSize + "px monospace";
    rCtx.fillStyle = "rgba(0,255,65," + alpha.toFixed(3) + ")";
    rCtx.fillText(g.text, 0, 0);
    // scanline effect: thin horizontal line through the text
    if(glitch){
      rCtx.fillStyle = "rgba(0,255,65,0.06)";
      rCtx.fillRect(-2*dpr, -g.fontSize*0.3, rCtx.measureText(g.text).width+4*dpr, 1*dpr);
    }
    rCtx.restore();
  }
}

function drawRadar(ts){
  var dpr = window.devicePixelRatio||1;
  var W = rCanvas.width, H = rCanvas.height;
  var cx = W/2, cy = H/2;
  var maxR = Math.min(cx, cy)*0.9;

  rCtx.clearRect(0,0,W,H);

  // ── flickering ghost MAC addresses in background ──
  drawGhosts(W, H, dpr);

  // ── subtle grid lines (crosshair) ──
  rCtx.strokeStyle = "rgba(0,255,65,0.06)";
  rCtx.lineWidth = 1*dpr;
  rCtx.beginPath(); rCtx.moveTo(cx,cy-maxR); rCtx.lineTo(cx,cy+maxR); rCtx.stroke();
  rCtx.beginPath(); rCtx.moveTo(cx-maxR,cy); rCtx.lineTo(cx+maxR,cy); rCtx.stroke();
  // diagonal crosshairs
  var d45 = maxR*0.707;
  rCtx.beginPath(); rCtx.moveTo(cx-d45,cy-d45); rCtx.lineTo(cx+d45,cy+d45); rCtx.stroke();
  rCtx.beginPath(); rCtx.moveTo(cx+d45,cy-d45); rCtx.lineTo(cx-d45,cy+d45); rCtx.stroke();

  // ── distance rings with glow ──
  for(var ri=0;ri<RINGS.length;ri++){
    var r = (Math.log(RINGS[ri]+1)/Math.log(MAX_RING+1))*maxR;
    // outer glow
    rCtx.beginPath();
    rCtx.arc(cx,cy,r,0,Math.PI*2);
    rCtx.strokeStyle = "rgba(0,255,65,0.08)";
    rCtx.lineWidth = 3*dpr;
    rCtx.stroke();
    // crisp ring
    rCtx.beginPath();
    rCtx.arc(cx,cy,r,0,Math.PI*2);
    rCtx.strokeStyle = "rgba(0,255,65,0.2)";
    rCtx.lineWidth = 1*dpr;
    rCtx.stroke();
    // labels at top and right
    rCtx.fillStyle = "rgba(0,255,65,0.45)";
    rCtx.font = (10*dpr)+"px monospace";
    rCtx.fillText(RINGS[ri]+"m", cx+r+4*dpr, cy-4*dpr);
    rCtx.fillText(RINGS[ri]+"m", cx+4*dpr, cy-r-4*dpr);
  }

  // ── outer ring decorative tick marks ──
  rCtx.strokeStyle = "rgba(0,255,65,0.15)";
  rCtx.lineWidth = 1*dpr;
  for(var deg=0; deg<360; deg+=10){
    var a = deg*Math.PI/180;
    var inner = deg%30===0 ? maxR*0.92 : maxR*0.96;
    rCtx.beginPath();
    rCtx.moveTo(cx+Math.cos(a)*inner, cy+Math.sin(a)*inner);
    rCtx.lineTo(cx+Math.cos(a)*maxR, cy+Math.sin(a)*maxR);
    rCtx.stroke();
  }
  // degree labels at 30° intervals
  rCtx.fillStyle = "rgba(0,255,65,0.2)";
  rCtx.font = (8*dpr)+"px monospace";
  for(var deg2=0; deg2<360; deg2+=30){
    var a2 = deg2*Math.PI/180;
    var lx = cx+Math.cos(a2)*(maxR+12*dpr);
    var ly = cy+Math.sin(a2)*(maxR+12*dpr);
    rCtx.fillText(deg2+"\u00B0", lx-10*dpr, ly+4*dpr);
  }

  // ── sweep with multi-layer trail ──
  sweepAngle = ((ts % SWEEP_PERIOD)/SWEEP_PERIOD)*Math.PI*2;
  if(rCtx.createConicGradient){
    // wide dim trail
    var trailLen1 = Math.PI*0.6;
    var grad1 = rCtx.createConicGradient(sweepAngle - trailLen1, cx, cy);
    grad1.addColorStop(0, "rgba(0,255,65,0)");
    grad1.addColorStop(0.7, "rgba(0,255,65,0.03)");
    grad1.addColorStop(1, "rgba(0,255,65,0.08)");
    rCtx.beginPath(); rCtx.moveTo(cx,cy);
    rCtx.arc(cx,cy,maxR, sweepAngle-trailLen1, sweepAngle);
    rCtx.closePath(); rCtx.fillStyle = grad1; rCtx.fill();
    // narrow bright trail
    var trailLen2 = Math.PI*0.25;
    var grad2 = rCtx.createConicGradient(sweepAngle - trailLen2, cx, cy);
    grad2.addColorStop(0, "rgba(0,255,65,0)");
    grad2.addColorStop(0.5, "rgba(0,255,65,0.06)");
    grad2.addColorStop(1, "rgba(0,255,65,0.22)");
    rCtx.beginPath(); rCtx.moveTo(cx,cy);
    rCtx.arc(cx,cy,maxR, sweepAngle-trailLen2, sweepAngle);
    rCtx.closePath(); rCtx.fillStyle = grad2; rCtx.fill();
  } else {
    // fallback for older browsers without createConicGradient
    rCtx.beginPath(); rCtx.moveTo(cx,cy);
    rCtx.arc(cx,cy,maxR, sweepAngle-Math.PI*0.4, sweepAngle);
    rCtx.closePath(); rCtx.fillStyle = "rgba(0,255,65,0.08)"; rCtx.fill();
  }

  // ── sweep line with glow ──
  var sx = cx+Math.cos(sweepAngle)*maxR, sy = cy+Math.sin(sweepAngle)*maxR;
  // glow layer
  rCtx.beginPath(); rCtx.moveTo(cx,cy); rCtx.lineTo(sx,sy);
  rCtx.strokeStyle = "rgba(0,255,65,0.25)";
  rCtx.lineWidth = 6*dpr;
  rCtx.stroke();
  // main line
  rCtx.beginPath(); rCtx.moveTo(cx,cy); rCtx.lineTo(sx,sy);
  rCtx.strokeStyle = "rgba(0,255,65,0.85)";
  rCtx.lineWidth = 2*dpr;
  rCtx.stroke();
  // bright tip
  rCtx.beginPath(); rCtx.arc(sx,sy,3*dpr,0,Math.PI*2);
  rCtx.fillStyle = "#00ff41"; rCtx.fill();

  // ── HUD corner brackets ──
  var cb = 20*dpr, co = 8*dpr;
  rCtx.strokeStyle = "rgba(0,255,65,0.3)";
  rCtx.lineWidth = 2*dpr;
  // top-left
  rCtx.beginPath(); rCtx.moveTo(co,co+cb); rCtx.lineTo(co,co); rCtx.lineTo(co+cb,co); rCtx.stroke();
  // top-right
  rCtx.beginPath(); rCtx.moveTo(W-co-cb,co); rCtx.lineTo(W-co,co); rCtx.lineTo(W-co,co+cb); rCtx.stroke();
  // bottom-left
  rCtx.beginPath(); rCtx.moveTo(co,H-co-cb); rCtx.lineTo(co,H-co); rCtx.lineTo(co+cb,H-co); rCtx.stroke();
  // bottom-right
  rCtx.beginPath(); rCtx.moveTo(W-co-cb,H-co); rCtx.lineTo(W-co,H-co); rCtx.lineTo(W-co,H-co-cb); rCtx.stroke();

  // ── centre marker with pulsing ring ──
  var cPulse = 1 + 0.15*Math.sin(ts/500);
  rCtx.beginPath(); rCtx.arc(cx,cy,8*dpr*cPulse,0,Math.PI*2);
  rCtx.strokeStyle = "rgba(0,255,65,0.3)";
  rCtx.lineWidth = 1*dpr; rCtx.stroke();
  rCtx.beginPath(); rCtx.arc(cx,cy,3*dpr,0,Math.PI*2);
  rCtx.fillStyle = "#00ff41"; rCtx.fill();
  rCtx.font = "bold "+(10*dpr)+"px monospace";
  rCtx.fillStyle = "#00ff41";
  rCtx.fillText("YOU",cx+10*dpr,cy+4*dpr);

  // ── ping ripples (expand outward when new device detected) ──
  var now = Date.now();
  for(var pi=pingRipples.length-1; pi>=0; pi--){
    var p = pingRipples[pi];
    var age = now - p.born;
    if(age > 1200){ pingRipples.splice(pi,1); continue; }
    var progress = age/1200;
    var pr = p.r + (p.maxR - p.r)*progress;
    var pa = (1-progress)*0.4;
    rCtx.beginPath(); rCtx.arc(p.cx,p.cy,pr,0,Math.PI*2);
    rCtx.strokeStyle = hexToRgba(p.color, pa);
    rCtx.lineWidth = 2*dpr; rCtx.stroke();
  }

  // ── device dots ──
  var addrs = Object.keys(devices);
  for(var i=0;i<addrs.length;i++){
    var dev = devices[addrs[i]];
    var angle = (hashAddr(dev.address)%3600)/3600*Math.PI*2;
    var dist = dev.est_distance;
    var r2 = distToRadius(dist, maxR);
    var dx = cx + Math.cos(angle)*r2;
    var dy = cy + Math.sin(angle)*r2;
    dev._rx = dx; dev._ry = dy;

    var col = dotColor(dist);
    var baseSize = 4*dpr;
    var age2 = now - (dev._updateTs||0);
    var pulse = age2 < 1500 ? 1 + 0.6*(1 - age2/1500) : 1;
    if(hoveredAddr === dev.address) pulse = Math.max(pulse, 1.6);
    var sz = baseSize * pulse;

    // outer glow ring
    rCtx.beginPath(); rCtx.arc(dx,dy,sz+6*dpr,0,Math.PI*2);
    rCtx.fillStyle = hexToRgba(col,0.06); rCtx.fill();
    // inner glow
    rCtx.beginPath(); rCtx.arc(dx,dy,sz+3*dpr,0,Math.PI*2);
    rCtx.fillStyle = hexToRgba(col,0.15); rCtx.fill();
    // core dot
    rCtx.beginPath(); rCtx.arc(dx,dy,sz,0,Math.PI*2);
    rCtx.fillStyle = col; rCtx.fill();
    // bright center
    rCtx.beginPath(); rCtx.arc(dx,dy,sz*0.4,0,Math.PI*2);
    rCtx.fillStyle = hexToRgba("#ffffff",0.5); rCtx.fill();

    // connecting line from center to dot (very faint)
    rCtx.beginPath(); rCtx.moveTo(cx,cy); rCtx.lineTo(dx,dy);
    rCtx.strokeStyle = hexToRgba(col,0.07);
    rCtx.lineWidth = 1*dpr; rCtx.stroke();

    // label
    if(pulse > 1.3 || hoveredAddr === dev.address){
      rCtx.fillStyle = "#e0e0e0";
      rCtx.font = (9*dpr)+"px monospace";
      var lbl = dev.name && dev.name !== "Unknown" ? dev.name.substring(0,14) : dev.address.substring(0,8);
      rCtx.fillText(lbl, dx+sz+6*dpr, dy+3*dpr);
      // show distance under label
      if(dist!=null && dist!==""){
        rCtx.fillStyle = hexToRgba(col,0.7);
        rCtx.font = (8*dpr)+"px monospace";
        rCtx.fillText("~"+Number(dist).toFixed(1)+"m", dx+sz+6*dpr, dy+14*dpr);
      }
    }
  }

  // ── HUD readouts in corners ──
  var devCount = Object.keys(devices).length;
  rCtx.fillStyle = "rgba(0,255,65,0.35)";
  rCtx.font = (9*dpr)+"px monospace";
  rCtx.fillText("DEVICES: "+devCount, co+4*dpr, co+cb+14*dpr);
  rCtx.fillText("RANGE: "+MAX_RING+"m", W-co-70*dpr, co+cb+14*dpr);

  requestAnimationFrame(drawRadar);
}

// spawn a ping ripple when a new device is detected or updated
function spawnPing(dev, cx, cy, maxR){
  var angle = (hashAddr(dev.address)%3600)/3600*Math.PI*2;
  var dist = dev.est_distance;
  var r2 = distToRadius(dist, maxR);
  var dpr = window.devicePixelRatio||1;
  pingRipples.push({
    cx: cx + Math.cos(angle)*r2,
    cy: cy + Math.sin(angle)*r2,
    r: 4*dpr, maxR: 25*dpr,
    color: dotColor(dist),
    born: Date.now()
  });
}

requestAnimationFrame(drawRadar);

/* ── radar hit test for tooltip ─────────────────────────── */
rCanvas.addEventListener("mousemove", function(e){
  var rect = rCanvas.getBoundingClientRect();
  var dpr = window.devicePixelRatio||1;
  var mx = (e.clientX - rect.left)*dpr;
  var my = (e.clientY - rect.top)*dpr;
  var hit = null;
  var addrs = Object.keys(devices);
  for(var i=0;i<addrs.length;i++){
    var d = devices[addrs[i]];
    if(d._rx===undefined) continue;
    var dx=d._rx-mx, dy=d._ry-my;
    if(Math.sqrt(dx*dx+dy*dy) < 12*dpr){ hit=d; break; }
  }
  if(hit){
    hoveredAddr = hit.address;
    showTooltip(hit, e.clientX, e.clientY);
  } else {
    hoveredAddr = null;
    hideTooltip();
  }
});
rCanvas.addEventListener("mouseleave", function(){
  hoveredAddr = null;
  hideTooltip();
});

/* ================================================================
   Leaflet Map
   ================================================================ */
var map = null;
var scannerMarker = null;
var devMarkers = {};

function initMap(){
  if(map) return;
  map = L.map("map",{zoomControl:true}).setView([0,0],16);
  L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png",{
    attribution:'&copy; OpenStreetMap',maxZoom:19
  }).addTo(map);
}

function updateScannerPos(lat, lon){
  if(!map) initMap();
  var ll = [lat,lon];
  if(!scannerMarker){
    scannerMarker = L.circleMarker(ll,{radius:8,color:"#2196f3",
      fillColor:"#2196f3",fillOpacity:0.7,weight:2}).addTo(map);
    scannerMarker.bindPopup("Scanner position");
    map.setView(ll, 17);
  } else {
    scannerMarker.setLatLng(ll);
    map.setView(ll);
  }
}

function updateDevMarker(dev){
  var gps = dev.best_gps;
  if(!gps || !gps.lat || !gps.lon) return;
  if(!map) initMap();
  var ll = [gps.lat, gps.lon];
  var col = dotColor(dev.est_distance);
  if(devMarkers[dev.address]){
    devMarkers[dev.address].setLatLng(ll);
    devMarkers[dev.address].setStyle({color:col,fillColor:col});
  } else {
    var m = L.circleMarker(ll,{radius:6,color:col,fillColor:col,
      fillOpacity:0.8,weight:1}).addTo(map);
    m.bindPopup("<b>"+(dev.name||"Unknown")+"</b><br>"+dev.address);
    devMarkers[dev.address] = m;
  }
}

function showMap(){
  var mw = document.getElementById("map-wrap");
  if(!mw.classList.contains("hidden")) return;
  mw.classList.remove("hidden");
  document.getElementById("radar-wrap").classList.remove("full");
  resizeCanvas();
  if(map) setTimeout(function(){ map.invalidateSize(); },100);
}

/* ================================================================
   Device Table
   ================================================================ */
var tbody = document.getElementById("dev-tbody");
var rowMap = {};

function updateTable(){
  var list = Object.values(devices);
  list.sort(function(a,b){
    var va = a[sortCol], vb = b[sortCol];
    if(va==null||va==="") va = sortAsc ? Infinity : -Infinity;
    if(vb==null||vb==="") vb = sortAsc ? Infinity : -Infinity;
    if(typeof va === "string" || typeof vb === "string"){
      var sa = String(va===Infinity||va===-Infinity?"":va);
      var sb = String(vb===Infinity||vb===-Infinity?"":vb);
      return sortAsc ? sa.localeCompare(sb) : sb.localeCompare(sa);
    }
    return sortAsc ? va-vb : vb-va;
  });
  for(var i=0;i<list.length;i++){
    var d = list[i];
    var tr = rowMap[d.address];
    if(!tr){
      tr = document.createElement("tr");
      tr.setAttribute("data-addr", d.address);
      for(var c=0;c<7;c++) tr.appendChild(document.createElement("td"));
      tr.addEventListener("mouseenter", (function(addr){
        return function(){ hoveredAddr=addr; showTooltipForAddr(addr); };
      })(d.address));
      tr.addEventListener("mousemove", function(e){
        var tip=document.getElementById("tooltip");
        positionTooltip(tip,e.clientX,e.clientY);
      });
      tr.addEventListener("mouseleave", function(){
        hoveredAddr=null; hideTooltip();
      });
      rowMap[d.address] = tr;
    }
    var cells = tr.children;
    cells[0].textContent = d.address;
    cells[1].textContent = d.name||"Unknown";
    cells[2].textContent = d.rssi!=null ? d.rssi+" dBm" : "";
    cells[3].textContent = d.avg_rssi!=null ? d.avg_rssi+" dBm" : "";
    cells[4].textContent = (d.est_distance!=null&&d.est_distance!=="") ? "~"+Number(d.est_distance).toFixed(1)+"m" : "";
    cells[5].textContent = d.times_seen ? d.times_seen+"x" : "";
    cells[6].textContent = d.last_seen||"";
    // ensure row is in DOM at correct position
    if(tr.parentNode !== tbody){
      tbody.appendChild(tr);
    }
  }
  // reorder rows
  for(var j=0;j<list.length;j++){
    var row = rowMap[list[j].address];
    tbody.appendChild(row);
  }
}

// sortable columns
document.querySelectorAll("#dev-table th").forEach(function(th){
  th.addEventListener("click", function(){
    var col = th.getAttribute("data-col");
    if(sortCol===col) sortAsc=!sortAsc;
    else { sortCol=col; sortAsc=false; }
    updateTable();
  });
});

/* ================================================================
   Tooltip
   ================================================================ */
function showTooltip(dev, x, y){
  var tip = document.getElementById("tooltip");
  var html = "";
  html += '<span class="lbl">Address:</span> <span class="val">'+esc(dev.address)+'</span><br>';
  html += '<span class="lbl">Name:</span> <span class="val">'+esc(dev.name||"Unknown")+'</span><br>';
  html += '<span class="lbl">RSSI:</span> <span class="val">'+(dev.rssi!=null?dev.rssi+" dBm":"N/A");
  if(dev.avg_rssi!=null) html += ' (avg: '+dev.avg_rssi+' dBm)';
  html += '</span><br>';
  html += '<span class="lbl">TX Power:</span> <span class="val">'+(dev.tx_power!=null?dev.tx_power+' dBm':'N/A')+'</span><br>';
  html += '<span class="lbl">Distance:</span> <span class="val">'+((dev.est_distance!=null&&dev.est_distance!=="")?"~"+Number(dev.est_distance).toFixed(1)+" m":"Unknown")+'</span><br>';
  if(dev.best_gps && dev.best_gps.lat){
    html += '<span class="lbl">Best GPS:</span> <span class="val">'+dev.best_gps.lat.toFixed(6)+', '+dev.best_gps.lon.toFixed(6)+'</span><br>';
  }
  if(dev.manufacturer_data){
    html += '<span class="lbl">Mfr Data:</span> <span class="val">'+esc(dev.manufacturer_data)+'</span><br>';
  }
  if(dev.service_uuids){
    html += '<span class="lbl">Services:</span> <span class="val">'+esc(dev.service_uuids)+'</span><br>';
  }
  html += '<span class="lbl">Seen:</span> <span class="val">'+(dev.times_seen||0)+'x</span>';
  if(dev.resolved===true) html += '<br><span class="val" style="color:var(--green)">IRK RESOLVED</span>';
  tip.innerHTML = html;
  tip.style.display = "block";
  positionTooltip(tip, x, y);
}

function showTooltipForAddr(addr){
  var d = devices[addr];
  if(!d) return;
  var tr = rowMap[addr];
  if(!tr) return;
  var rect = tr.getBoundingClientRect();
  showTooltip(d, rect.right+10, rect.top);
}

function positionTooltip(tip, x, y){
  var tw = tip.offsetWidth, th2 = tip.offsetHeight;
  var wx = window.innerWidth, wy = window.innerHeight;
  var lx = x+14, ly = y+14;
  if(lx+tw > wx-8) lx = x - tw - 14;
  if(ly+th2 > wy-8) ly = y - th2 - 14;
  if(lx<4) lx=4; if(ly<4) ly=4;
  tip.style.left = lx+"px";
  tip.style.top  = ly+"px";
}

function hideTooltip(){
  document.getElementById("tooltip").style.display="none";
}

function esc(s){ if(!s) return ""; var d=document.createElement("div"); d.textContent=s; return d.innerHTML; }

/* ================================================================
   Header / Status
   ================================================================ */
function updateStatus(data){
  if(data.unique_count!=null) document.getElementById("s-unique").textContent = data.unique_count;
  if(data.total_detections!=null) document.getElementById("s-total").textContent = data.total_detections;
  if(data.elapsed!=null){
    var m = Math.floor(data.elapsed/60), s = Math.floor(data.elapsed%60);
    document.getElementById("s-elapsed").textContent = (m<10?"0":"")+m+":"+(s<10?"0":"")+s;
  }
  var dot = document.getElementById("s-dot");
  if(data.scanning===false){ dot.style.color="var(--red)"; }
  else { dot.style.color="var(--green)"; }
}

/* ================================================================
   Scan complete overlay
   ================================================================ */
function showOverlay(data){
  var el = document.getElementById("overlay");
  document.getElementById("ov-elapsed").textContent = "Elapsed: "+Number(data.elapsed).toFixed(1)+"s";
  document.getElementById("ov-total").textContent = "Total detections: "+(data.total_detections||0);
  document.getElementById("ov-unique").textContent = "Unique devices: "+(data.unique_devices||0);
  el.style.display = "flex";
}

/* ================================================================
   Socket.IO
   ================================================================ */
var socket = io("http://"+window.location.hostname+":"+WSPORT, {transports:["websocket","polling"]});

socket.on("connect", function(){
  // fetch full state on connect
  fetch("http://"+window.location.hostname+":"+WSPORT+"/api/state").then(function(r){return r.json();}).then(function(state){
    if(state.devices){
      var addrs = Object.keys(state.devices);
      for(var i=0;i<addrs.length;i++){
        var d = state.devices[addrs[i]];
        d._updateTs = Date.now();
        devices[d.address] = d;
        updateDevMarker(d);
      }
      updateTable();
    }
    if(state.status) updateStatus(state.status);
    if(state.gps && state.gps.lat!=null){
      hasGPS = true;
      scannerGPS = state.gps;
      showMap();
      updateScannerPos(state.gps.lat, state.gps.lon);
    }
  }).catch(function(){});
});

socket.on("device_update", function(d){
  var isNew = !devices[d.address];
  d._updateTs = Date.now();
  devices[d.address] = d;
  updateDevMarker(d);
  updateTable();
  // spawn a ping ripple for new devices
  if(isNew){
    var dpr = window.devicePixelRatio||1;
    var W = rCanvas.width, H = rCanvas.height;
    var cxr = W/2, cyr = H/2;
    var maxRr = Math.min(cxr,cyr)*0.9;
    spawnPing(d, cxr, cyr, maxRr);
  }
});

socket.on("gps_update", function(g){
  if(g && g.lat!=null && g.lon!=null){
    scannerGPS = g;
    if(!hasGPS){ hasGPS=true; showMap(); }
    updateScannerPos(g.lat, g.lon);
  }
});

socket.on("scan_status", function(data){
  updateStatus(data);
});

socket.on("scan_complete", function(data){
  updateStatus({scanning:false, elapsed:data.elapsed,
    total_detections:data.total_detections, unique_count:data.unique_devices});
  showOverlay(data);
});

})();
</script>
""" + r"""{% endraw %}""" + r"""
</body>
</html>
"""


def _timestamp() -> str:
    """Return an ISO 8601 timestamp with timezone offset."""
    return datetime.now().astimezone().strftime("%Y-%m-%dT%H:%M:%S%z")


def _mask_irk(irk_hex: str) -> str:
    """Mask an IRK hex string, showing only the first and last 4 characters."""
    if len(irk_hex) <= 8:
        return irk_hex
    return irk_hex[:4] + "..." + irk_hex[-4:]


class GpsdReader:
    """Lightweight gpsd client that reads GPS fixes over a TCP socket."""

    def __init__(self, host: str = "localhost", port: int = 2947):
        self._host = host
        self._port = port
        self._lock = threading.Lock()
        self._fix: Optional[dict] = None
        self._connected = False
        self._running = False
        self._thread: Optional[threading.Thread] = None

    @property
    def fix(self) -> Optional[dict]:
        with self._lock:
            return dict(self._fix) if self._fix else None

    @property
    def connected(self) -> bool:
        with self._lock:
            return self._connected

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread is not None:
            self._thread.join(timeout=2)

    def _run(self):
        while self._running:
            try:
                self._connect_and_read()
            except (OSError, ConnectionRefusedError, ConnectionResetError):
                pass
            with self._lock:
                self._connected = False
            if self._running:
                time.sleep(_GPS_RECONNECT_DELAY)

    def _connect_and_read(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(_GPS_SOCKET_TIMEOUT)
        try:
            sock.connect((self._host, self._port))
            with self._lock:
                self._connected = True
            sock.sendall(b'?WATCH={"enable":true,"json":true}\n')
            buf = ""
            while self._running:
                try:
                    data = sock.recv(4096)
                except socket.timeout:
                    continue
                if not data:
                    break
                buf += data.decode("utf-8", errors="replace")
                while "\n" in buf:
                    line, buf = buf.split("\n", 1)
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        msg = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if msg.get("class") == "TPV":
                        lat = msg.get("lat")
                        lon = msg.get("lon")
                        if lat is not None and lon is not None:
                            with self._lock:
                                self._fix = {
                                    "lat": lat,
                                    "lon": lon,
                                    "alt": msg.get("alt"),
                                }
        finally:
            sock.close()


class GuiServer:
    """Flask + SocketIO server for the GUI radar interface."""

    def __init__(self, port: int = 5000):
        if not _HAS_FLASK:
            raise ImportError(
                "GUI requires Flask and flask-socketio. "
                "Install with: pip install flask flask-socketio")
        self._port = port
        self._app = Flask(__name__)
        self._app.config['SECRET_KEY'] = os.urandom(24).hex()
        self._sio = SocketIO(self._app, async_mode='threading', cors_allowed_origins='*')
        self._thread = None
        self._devices = {}
        self._scan_status = {}
        self._gps_fix = None
        self._setup_routes()

    def _setup_routes(self):
        @self._app.route('/')
        def index():
            return render_template_string(_GUI_HTML, port=self._port)

        @self._app.route('/api/state')
        def state():
            return jsonify({
                'devices': dict(self._devices),
                'status': dict(self._scan_status) if self._scan_status else {},
                'gps': self._gps_fix,
            })

    def start(self):
        """Start the Flask server in a background thread."""
        started = threading.Event()
        actual_port = [self._port]

        def _serve():
            for p in range(self._port, self._port + 11):
                try:
                    actual_port[0] = p
                    started.set()
                    self._sio.run(self._app, host='0.0.0.0', port=p,
                                  allow_unsafe_werkzeug=True,
                                  log_output=False)
                    return
                except OSError:
                    started.clear()
                    continue
            actual_port[0] = -1
            started.set()

        self._thread = threading.Thread(target=_serve, daemon=True)
        self._thread.start()

        # Wait for server to bind (or all ports to fail)
        started.wait(timeout=5)
        time.sleep(0.3)  # small extra delay for server to be ready
        self._port = actual_port[0]
        if self._port == -1:
            print("Error: Could not find open port for GUI server")
            sys.exit(1)

        url = f"http://localhost:{self._port}"
        print(f"  GUI server started at {url}")
        try:
            webbrowser.open(url)
        except Exception:
            print(f"  Could not open browser — navigate to {url}")

    def emit_device(self, data: dict):
        """Push a device update to all connected clients."""
        self._devices[data['address']] = data
        self._sio.emit('device_update', data)

    def emit_gps(self, fix: dict):
        """Push scanner GPS position to all connected clients."""
        self._gps_fix = fix
        self._sio.emit('gps_update', fix)

    def emit_status(self, status: dict):
        """Push scan status to all connected clients."""
        self._scan_status = status
        self._sio.emit('scan_status', status)

    def emit_complete(self, summary: dict):
        """Push scan complete event."""
        self._sio.emit('scan_complete', summary)


class BLEScanner:
    def __init__(self, target_mac: Optional[str], timeout: float,
                 irks: Optional[List[bytes]] = None,
                 output_format: Optional[str] = None,
                 output_file: Optional[str] = None,
                 verbose: bool = False,
                 quiet: bool = False,
                 min_rssi: Optional[int] = None,
                 rssi_window: int = 1,
                 active: bool = False,
                 environment: str = "free_space",
                 alert_within: Optional[float] = None,
                 log_file: Optional[str] = None,
                 tui: bool = False,
                 adapters: Optional[List[str]] = None,
                 gps: bool = True,
                 ref_rssi: Optional[int] = None,
                 name_filter: Optional[str] = None,
                 gui: bool = False,
                 gui_port: int = 5000):
        self.target_mac = target_mac.upper() if target_mac else None
        self.targeted = target_mac is not None
        self.timeout = timeout
        self.seen_count = 0
        self.unique_devices: Dict[str, int] = {}
        self.running = True
        # IRK mode — supports one or more keys
        self.irks = irks or []
        self.irk_mode = len(self.irks) > 0
        self.resolved_devices: Dict[str, int] = {}
        self.rpa_count = 0
        self.non_rpa_warned: Set[str] = set()
        # Options
        self.verbose = verbose
        self.quiet = quiet
        self.min_rssi = min_rssi
        self.output_format = output_format
        self.output_file = output_file
        self.records: List[dict] = []
        # RSSI averaging
        self.rssi_window = max(1, rssi_window)
        self.rssi_history: Dict[str, deque] = {}
        # Scanning mode
        self.active = active
        # Environment for distance estimation
        self.environment = environment
        # Proximity alerts
        self.alert_within = alert_within
        # Real-time CSV log
        self.log_file = log_file
        self._log_writer = None
        self._log_fh = None
        # Only accumulate records in memory when batch output is requested.
        # For long-running scans without --output, this prevents unbounded
        # memory growth.  Real-time logging (--log) writes directly to disk.
        self._accumulate_records = (output_format is not None)
        # TUI mode
        self.tui = tui
        self.tui_devices: Dict[str, dict] = {}
        self._tui_screen = None
        self._tui_start = 0.0
        # Multi-adapter
        self.adapters = adapters
        # Reference RSSI calibration
        self.ref_rssi = ref_rssi
        # Name filter
        self.name_filter = name_filter
        # GPS
        self._gps = GpsdReader() if gps else None
        self.device_best_gps: Dict[str, dict] = {}
        # Thread safety for detection callback (multi-adapter)
        self._cb_lock = threading.Lock()
        # GUI mode
        self.gui = gui
        self.gui_port = gui_port
        self._gui_server = None

    def _avg_rssi(self, addr: str, rssi: int) -> int:
        """Update RSSI sliding window for a device and return the average."""
        if addr not in self.rssi_history:
            self.rssi_history[addr] = deque(maxlen=self.rssi_window)
        self.rssi_history[addr].append(rssi)
        return round(sum(self.rssi_history[addr]) / len(self.rssi_history[addr]))

    def _build_record(self, device: BLEDevice, adv: AdvertisementData,
                      resolved: Optional[bool] = None,
                      avg_rssi: Optional[int] = None) -> dict:
        """Build a record dict from device/adv data."""
        rssi = adv.rssi
        tx_power = adv.tx_power
        rssi_for_dist = avg_rssi if avg_rssi is not None else rssi
        dist = _estimate_distance(rssi_for_dist, tx_power, self.environment,
                                  ref_rssi=self.ref_rssi)

        mfr_data = ""
        if adv.manufacturer_data:
            parts = []
            for mfr_id, data in adv.manufacturer_data.items():
                parts.append(f"0x{mfr_id:04X}:{data.hex()}")
            mfr_data = "; ".join(parts)

        service_uuids = ", ".join(adv.service_uuids) if adv.service_uuids else ""

        return {
            "timestamp": _timestamp(),
            "address": device.address,
            "name": device.name or "Unknown",
            "rssi": rssi,
            "avg_rssi": avg_rssi if avg_rssi is not None else "",
            "tx_power": tx_power if tx_power is not None else "",
            "est_distance": round(dist, 2) if dist is not None else "",
            "latitude": "",
            "longitude": "",
            "gps_altitude": "",
            "manufacturer_data": mfr_data,
            "service_uuids": service_uuids,
            "resolved": resolved if resolved is not None else "",
        }

    def _record_device(self, device: BLEDevice, adv: AdvertisementData,
                       resolved: Optional[bool] = None,
                       avg_rssi: Optional[int] = None) -> dict:
        """Build a record, optionally append to self.records, write to live
        log, and update TUI state.  Returns the record dict."""
        record = self._build_record(device, adv, resolved=resolved, avg_rssi=avg_rssi)

        # Stamp GPS coordinates on this record
        if self._gps is not None:
            fix = self._gps.fix
            if fix is not None:
                record["latitude"] = fix["lat"]
                record["longitude"] = fix["lon"]
                record["gps_altitude"] = fix["alt"] if fix["alt"] is not None else ""
                # Track per-device best GPS (strongest RSSI = closest proximity)
                addr = (device.address or "").upper()
                current_rssi = adv.rssi
                best = self.device_best_gps.get(addr)
                if best is None or current_rssi > best["rssi"]:
                    self.device_best_gps[addr] = {
                        "lat": fix["lat"],
                        "lon": fix["lon"],
                        "rssi": current_rssi,
                    }

        # Accumulate records only when batch output is needed
        if self._accumulate_records:
            self.records.append(record)

        # Real-time CSV logging
        if self._log_writer is not None:
            self._log_writer.writerow(record)
            self._log_fh.flush()

        # Update TUI device state
        if self.tui:
            addr = (device.address or "").upper()
            self.tui_devices[addr] = {
                "address": device.address,
                "name": device.name or "Unknown",
                "rssi": adv.rssi,
                "avg_rssi": avg_rssi,
                "est_distance": record["est_distance"],
                "times_seen": self.unique_devices.get(addr, 0),
                "last_seen": time.strftime("%H:%M:%S"),
                "resolved": resolved,
            }

        # Update GUI
        if self.gui and self._gui_server is not None:
            addr = (device.address or "").upper()
            best_gps = self.device_best_gps.get(addr)
            self._gui_server.emit_device({
                'address': device.address,
                'name': device.name or 'Unknown',
                'rssi': adv.rssi,
                'avg_rssi': avg_rssi,
                'tx_power': adv.tx_power,
                'est_distance': record['est_distance'],
                'latitude': record.get('latitude', ''),
                'longitude': record.get('longitude', ''),
                'best_gps': best_gps,
                'manufacturer_data': record.get('manufacturer_data', ''),
                'service_uuids': record.get('service_uuids', ''),
                'times_seen': self.unique_devices.get(addr, 0),
                'last_seen': time.strftime('%H:%M:%S'),
                'resolved': resolved,
                'timestamp': record['timestamp'],
            })

        # Proximity alert
        if self.alert_within is not None and record["est_distance"] != "":
            if record["est_distance"] <= self.alert_within:
                if self.tui and self._tui_screen is not None:
                    curses.beep()
                elif not self.quiet and not self.gui:
                    print(f"\a  ** PROXIMITY ALERT ** {device.address} "
                          f"within ~{record['est_distance']:.1f}m "
                          f"(threshold: {self.alert_within}m)")

        return record

    def _print_device(self, device: BLEDevice, adv: AdvertisementData,
                      label: str, resolved: Optional[bool] = None,
                      avg_rssi: Optional[int] = None):
        # Always record for output / log / TUI
        record = self._record_device(device, adv, resolved=resolved, avg_rssi=avg_rssi)

        if self.quiet or self.tui or self.gui:
            return

        rssi = adv.rssi
        dist = record["est_distance"]

        print(f"\n{'='*60}")
        print(f"  {label}")
        print(f"{'='*60}")
        addr_line = f"  Address      : {device.address}"
        if resolved is True:
            addr_line += "  << IRK MATCH >>"
        elif resolved is False:
            addr_line += "  (no match)"
        print(addr_line)
        print(f"  Name         : {device.name or 'Unknown'}")
        if avg_rssi is not None and self.rssi_window > 1:
            addr_key = (device.address or "").upper()
            n_samples = len(self.rssi_history.get(addr_key, []))
            print(f"  RSSI         : {rssi} dBm  (avg: {avg_rssi} dBm over {n_samples} readings)")
        else:
            print(f"  RSSI         : {rssi} dBm")
        tx_power = adv.tx_power
        print(f"  TX Power     : {tx_power if tx_power is not None else 'N/A'} dBm")
        if dist != "":
            print(f"  Est. Distance: ~{dist:.1f} m")
        if adv.local_name and adv.local_name != device.name:
            print(f"  Local Name   : {adv.local_name}")
        if adv.manufacturer_data:
            for mfr_id, data in adv.manufacturer_data.items():
                print(f"  Manufacturer : 0x{mfr_id:04X} -> {data.hex()}")
        if adv.service_uuids:
            print(f"  Services     : {', '.join(adv.service_uuids)}")
        if adv.service_data:
            for uuid, data in adv.service_data.items():
                print(f"  Service Data : {uuid} -> {data.hex()}")
        if adv.platform_data:
            for item in adv.platform_data:
                print(f"  Platform Data: {item}")
        addr_key = (device.address or "").upper()
        best_gps = self.device_best_gps.get(addr_key)
        if best_gps:
            print(f"  Best GPS     : {best_gps['lat']:.6f}, {best_gps['lon']:.6f}")
        print(f"  Timestamp    : {time.strftime('%H:%M:%S')}")
        print(f"{'='*60}")

    def detection_callback(self, device: BLEDevice, adv: AdvertisementData):
        with self._cb_lock:
            self._detection_callback_inner(device, adv)

    def _detection_callback_inner(self, device: BLEDevice,
                                  adv: AdvertisementData):
        addr = (device.address or "").upper()

        # Compute averaged RSSI when windowing is enabled
        avg_rssi = self._avg_rssi(addr, adv.rssi) if self.rssi_window > 1 else None
        effective_rssi = avg_rssi if avg_rssi is not None else adv.rssi

        # RSSI filtering — uses averaged RSSI when available
        if self.min_rssi is not None and effective_rssi < self.min_rssi:
            return

        # Name filtering (case-insensitive substring match)
        if self.name_filter is not None:
            name = device.name or ""
            if self.name_filter.lower() not in name.lower():
                return

        if self.irk_mode:
            self._irk_detection(device, adv, addr, avg_rssi=avg_rssi)
            return

        if self.targeted:
            if self.target_mac not in addr:
                return
            self.seen_count += 1
            self._print_device(device, adv,
                               f"TARGET FOUND  —  detection #{self.seen_count}",
                               avg_rssi=avg_rssi)
        else:
            times_seen = self.unique_devices.get(addr, 0) + 1
            self.unique_devices[addr] = times_seen
            self.seen_count += 1
            self._print_device(device, adv,
                               f"DEVICE #{len(self.unique_devices)}  —  seen {times_seen}x",
                               avg_rssi=avg_rssi)

    def _irk_detection(self, device: BLEDevice, adv: AdvertisementData,
                       addr: str, avg_rssi: Optional[int] = None):
        """Handle a detection in IRK resolution mode."""
        self.seen_count += 1

        is_uuid = len(addr.replace("-", "")) == 32 and ":" not in addr
        if is_uuid:
            if addr not in self.non_rpa_warned:
                self.non_rpa_warned.add(addr)
                if not self.quiet and not self.tui and not self.gui:
                    print(f"  [!] UUID address {addr} — cannot resolve (need real MAC)")
            return

        times_seen = self.unique_devices.get(addr, 0) + 1
        self.unique_devices[addr] = times_seen

        # Check address against all loaded IRKs
        resolved = False
        for irk in self.irks:
            if _resolve_rpa(irk, addr):
                resolved = True
                break

        if resolved:
            self.rpa_count += 1
            det_count = self.resolved_devices.get(addr, 0) + 1
            self.resolved_devices[addr] = det_count
            self._print_device(
                device, adv,
                f"IRK RESOLVED  —  match #{det_count} (addr seen {times_seen}x)",
                resolved=True, avg_rssi=avg_rssi,
            )
        else:
            if self.verbose:
                self._print_device(
                    device, adv,
                    f"IRK NO MATCH  —  addr seen {times_seen}x",
                    resolved=False, avg_rssi=avg_rssi,
                )

    # ------------------------------------------------------------------
    # TUI (curses)
    # ------------------------------------------------------------------

    def _redraw_tui(self, screen):
        """Redraw the TUI live table."""
        try:
            screen.erase()
            h, w = screen.getmaxyx()

            elapsed = time.time() - self._tui_start
            header = (f" btrpa-scan | Devices: {len(self.tui_devices)}"
                      f"  Detections: {self.seen_count}"
                      f"  Elapsed: {elapsed:.0f}s")
            if self.irk_mode:
                header += f"  IRK matches: {self.rpa_count}"
            screen.addnstr(0, 0, header.ljust(w - 1), w - 1,
                           curses.A_BOLD | curses.A_REVERSE)

            settings = f" {'active' if self.active else 'passive'}"
            if self.environment != "free_space":
                settings += f" | env: {self.environment}"
            if self.rssi_window > 1:
                settings += f" | rssi-avg: {self.rssi_window}"
            if self.min_rssi is not None:
                settings += f" | min-rssi: {self.min_rssi}"
            if self.alert_within is not None:
                settings += f" | alert: <{self.alert_within}m"
            if self._gps is not None:
                fix = self._gps.fix
                if fix is not None:
                    settings += f" | GPS: {fix['lat']:.5f},{fix['lon']:.5f}"
                elif self._gps.connected:
                    settings += " | GPS: no fix"
                else:
                    settings += " | GPS: offline"
            screen.addnstr(1, 0, settings, w - 1, curses.A_DIM)

            col_fmt = " {:<19s} {:<16s} {:>5s} {:>5s} {:>7s} {:>5s} {:>8s}"
            col_hdr = col_fmt.format(
                "Address", "Name", "RSSI", "Avg", "Dist", "Seen", "Last")
            screen.addnstr(3, 0, col_hdr, w - 1, curses.A_UNDERLINE)

            sorted_devs = sorted(
                self.tui_devices.values(),
                key=lambda d: d["rssi"], reverse=True,
            )

            row = 4
            for dev in sorted_devs:
                if row >= h - 1:
                    remaining = len(sorted_devs) - (row - 4)
                    screen.addnstr(
                        h - 1, 0,
                        f" ... {remaining} more (resize terminal)", w - 1)
                    break
                avg_str = str(dev["avg_rssi"]) if dev["avg_rssi"] is not None else ""
                dist_str = (f"~{dev['est_distance']:.1f}m"
                            if isinstance(dev["est_distance"], (int, float))
                            else "")
                line = col_fmt.format(
                    (dev["address"] or "")[:18],
                    dev["name"][:15],
                    str(dev["rssi"]), avg_str, dist_str,
                    f"{dev['times_seen']}x",
                    dev["last_seen"],
                )
                attr = curses.A_NORMAL
                if dev.get("resolved") is True:
                    attr = curses.A_BOLD
                if (self.alert_within is not None
                        and isinstance(dev["est_distance"], (int, float))
                        and dev["est_distance"] <= self.alert_within):
                    attr |= curses.A_STANDOUT
                screen.addnstr(row, 0, line, w - 1, attr)
                row += 1

            footer = " Press Ctrl+C to stop"
            if self.log_file:
                footer += f"  |  Logging to {self.log_file}"
            screen.addnstr(h - 1, 0, footer, w - 1, curses.A_DIM)

            screen.refresh()
        except curses.error:
            pass

    # ------------------------------------------------------------------
    # Main scan flow
    # ------------------------------------------------------------------

    async def scan(self):
        # Install signal handlers inside the async context for clean
        # shutdown without the signal-handler / KeyboardInterrupt race.
        loop = asyncio.get_running_loop()
        if platform.system() != "Windows":
            loop.add_signal_handler(signal.SIGINT, self.stop)
            loop.add_signal_handler(signal.SIGTERM, self.stop)

        # Start GPS reader
        if self._gps is not None:
            self._gps.start()
            await asyncio.sleep(_GPS_STARTUP_DELAY)

        # Open real-time CSV log
        if self.log_file:
            self._log_fh = open(self.log_file, "w", newline="")
            self._log_writer = csv.DictWriter(self._log_fh,
                                              fieldnames=_FIELDNAMES)
            self._log_writer.writeheader()
            self._log_fh.flush()

        # GUI setup
        if self.gui:
            self._gui_server = GuiServer(port=self.gui_port)
            self._gui_server.start()

        # TUI setup
        if self.tui:
            self._tui_screen = curses.initscr()
            curses.noecho()
            curses.cbreak()
            curses.curs_set(0)
            if curses.has_colors():
                curses.start_color()
                curses.use_default_colors()

        elapsed = 0.0
        try:
            elapsed = await self._scan_loop()
        finally:
            # TUI cleanup
            if self._tui_screen is not None:
                curses.curs_set(1)
                curses.nocbreak()
                curses.echo()
                curses.endwin()
                self._tui_screen = None

            # Stop GPS reader
            if self._gps is not None:
                self._gps.stop()

            # Close log file
            if self._log_fh is not None:
                self._log_fh.close()
                self._log_fh = None
                self._log_writer = None

        # GUI scan complete
        if self.gui and self._gui_server is not None:
            self._gui_server.emit_status({
                'elapsed': round(elapsed, 1),
                'total_detections': self.seen_count,
                'unique_count': len(self.unique_devices),
                'scanning': False,
            })
            self._gui_server.emit_complete({
                'elapsed': round(elapsed, 1),
                'total_detections': self.seen_count,
                'unique_devices': len(self.unique_devices),
            })

        # Summary and output (printed after TUI is torn down)
        self._print_summary(elapsed)
        self._write_output()

    async def _scan_loop(self) -> float:
        """Run the BLE scanner and return elapsed seconds."""
        if not self.quiet and not self.tui and not self.gui:
            self._print_header()

        scanner_kwargs: dict = {"detection_callback": self.detection_callback}
        if self.active:
            scanner_kwargs["scanning_mode"] = "active"
        if self.irk_mode and platform.system() == "Darwin":
            # Undocumented CoreBluetooth API to retrieve real BD_ADDR
            # instead of CoreBluetooth UUIDs.  May break in future
            # Bleak releases.
            scanner_kwargs["cb"] = {"use_bdaddr": True}

        # Multi-adapter support
        scanners = []
        if self.adapters:
            for adapter in self.adapters:
                kw = {**scanner_kwargs, "adapter": adapter}
                scanners.append(BleakScanner(**kw))
        else:
            scanners.append(BleakScanner(**scanner_kwargs))

        for s in scanners:
            await s.start()

        start = time.time()
        self._tui_start = start
        try:
            if self.timeout == float('inf'):
                while self.running:
                    if self._tui_screen is not None:
                        self._redraw_tui(self._tui_screen)
                    if self.gui and self._gui_server is not None:
                        el = time.time() - start
                        self._gui_server.emit_status({
                            'elapsed': round(el, 1),
                            'total_detections': self.seen_count,
                            'unique_count': len(self.unique_devices),
                            'scanning': True,
                        })
                        if self._gps is not None:
                            fix = self._gps.fix
                            if fix is not None:
                                self._gui_server.emit_gps(fix)
                    await asyncio.sleep(
                        _TUI_REFRESH_INTERVAL if self.tui
                        else _SCAN_POLL_INTERVAL)
            else:
                while self.running and (time.time() - start) < self.timeout:
                    if self._tui_screen is not None:
                        self._redraw_tui(self._tui_screen)
                    if self.gui and self._gui_server is not None:
                        el = time.time() - start
                        self._gui_server.emit_status({
                            'elapsed': round(el, 1),
                            'total_detections': self.seen_count,
                            'unique_count': len(self.unique_devices),
                            'scanning': True,
                        })
                        if self._gps is not None:
                            fix = self._gps.fix
                            if fix is not None:
                                self._gui_server.emit_gps(fix)
                    await asyncio.sleep(_TIMED_SCAN_POLL_INTERVAL)
        except asyncio.CancelledError:
            pass
        finally:
            for s in scanners:
                await s.stop()

        return time.time() - start

    def _print_header(self):
        """Print scan configuration banner."""
        print(_BANNER)
        if self.irk_mode:
            n_irks = len(self.irks)
            if n_irks == 1:
                print("Mode: IRK RESOLUTION — resolving RPAs against provided IRK")
                print(f"  IRK: {_mask_irk(self.irks[0].hex())}")
            else:
                print(f"Mode: IRK RESOLUTION — resolving RPAs against {n_irks} IRKs")
                for i, irk in enumerate(self.irks, 1):
                    print(f"  IRK #{i}: {_mask_irk(irk.hex())}")
            _os = platform.system()
            if _os == "Darwin":
                print("  Note: using undocumented macOS API to retrieve real BT addresses")
            elif _os == "Linux":
                print("  Note: Linux/BlueZ — may require root or CAP_NET_ADMIN")
            elif _os == "Windows":
                print("  Note: Windows/WinRT — real MAC addresses available natively")
        elif self.targeted:
            print(f"Mode: TARGETED — searching for {self.target_mac}")
        else:
            print("Mode: DISCOVER ALL — showing every broadcasting device")
        scan_mode = "active" if self.active else "passive"
        print(f"Scanning: {scan_mode}", end="")
        if self.rssi_window > 1:
            print(f"  |  RSSI averaging: window of {self.rssi_window}")
        else:
            print()
        if self.active and platform.system() == "Darwin":
            print("  Note: CoreBluetooth always scans actively regardless of this flag")
        if self.environment != "free_space":
            print(f"Environment: {self.environment} "
                  f"(n={_ENV_PATH_LOSS[self.environment]})")
        if self.min_rssi is not None:
            print(f"Min RSSI: {self.min_rssi} dBm")
        if self.name_filter is not None:
            print(f"Name filter: \"{self.name_filter}\"")
        if self.alert_within is not None:
            print(f"Proximity alert: within {self.alert_within}m")
        if self.log_file:
            print(f"Live log: {self.log_file}")
        if self.adapters:
            print(f"Adapters: {', '.join(self.adapters)}")
        if self._gps is not None:
            fix = self._gps.fix
            if fix is not None:
                print(f"GPS: connected ({fix['lat']:.6f}, {fix['lon']:.6f})")
            elif self._gps.connected:
                print("GPS: waiting for fix")
            else:
                print("GPS: gpsd not available — continuing without GPS")
        elif self._gps is None:
            print("GPS: disabled")
        if self.timeout == float('inf'):
            print("Running continuously  |  Press Ctrl+C to stop")
        else:
            print(f"Timeout: {self.timeout}s  |  Press Ctrl+C to stop")
        print(f"{'—'*60}")

    def _print_summary(self, elapsed: float):
        """Print scan summary statistics."""
        print(f"\n{'—'*60}")
        print(f"Scan complete — {elapsed:.1f}s elapsed")
        print(f"  Total detections : {self.seen_count}")
        if self.irk_mode:
            print(f"  Unique addresses : {len(self.unique_devices)}")
            print(f"  IRK matches      : {self.rpa_count} detections "
                  f"across {len(self.resolved_devices)} address(es)")
            if self.resolved_devices:
                has_gps = any(a in self.device_best_gps for a in self.resolved_devices)
                print(f"\n  Resolved addresses:")
                if has_gps:
                    print(f"  {'Address':<20} {'Detections':>11}  {'Best GPS'}")
                    print(f"  {'—'*20} {'—'*11}  {'—'*24}")
                else:
                    print(f"  {'Address':<20} {'Detections':>11}")
                    print(f"  {'—'*20} {'—'*11}")
                for addr, count in sorted(self.resolved_devices.items(),
                                          key=lambda x: x[1], reverse=True):
                    line = f"  {addr:<20} {count:>10}x"
                    if has_gps:
                        bg = self.device_best_gps.get(addr)
                        gps_str = f"  {bg['lat']:.6f}, {bg['lon']:.6f}" if bg else ""
                        line += gps_str
                    print(line)
            if not self.resolved_devices:
                print("\n  No addresses resolved — the device may not be "
                      "broadcasting,")
                print("  or the IRK may be incorrect.")
        elif not self.targeted:
            print(f"  Unique devices   : {len(self.unique_devices)}")
            if self.unique_devices:
                has_gps = any(a in self.device_best_gps for a in self.unique_devices)
                if has_gps:
                    print(f"\n  {'Address':<40} {'Seen':>6}  {'Best GPS'}")
                    print(f"  {'—'*40} {'—'*6}  {'—'*24}")
                else:
                    print(f"\n  {'Address':<40} {'Seen':>6}")
                    print(f"  {'—'*40} {'—'*6}")
                for addr, count in sorted(self.unique_devices.items(),
                                          key=lambda x: x[1], reverse=True):
                    line = f"  {addr:<40} {count:>5}x"
                    if has_gps:
                        bg = self.device_best_gps.get(addr)
                        gps_str = f"  {bg['lat']:.6f}, {bg['lon']:.6f}" if bg else ""
                        line += gps_str
                    print(line)

    def _write_output(self):
        """Write batch output file (json / jsonl / csv)."""
        if not self.output_format or not self.records:
            if self.log_file:
                print(f"  Live log written to {self.log_file}")
            return

        filename = self.output_file or f"btrpa-scan-results.{self.output_format}"

        # Support writing to stdout with --output-file -
        if filename == "-":
            if self.output_format == "json":
                sys.stdout.write(json.dumps(self.records, indent=2) + "\n")
            elif self.output_format == "jsonl":
                for record in self.records:
                    sys.stdout.write(json.dumps(record) + "\n")
            elif self.output_format == "csv":
                writer = csv.DictWriter(sys.stdout, fieldnames=_FIELDNAMES)
                writer.writeheader()
                writer.writerows(self.records)
            return

        if self.output_format == "json":
            with open(filename, "w") as f:
                json.dump(self.records, f, indent=2)
        elif self.output_format == "jsonl":
            with open(filename, "w") as f:
                for record in self.records:
                    f.write(json.dumps(record) + "\n")
        elif self.output_format == "csv":
            with open(filename, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=_FIELDNAMES)
                writer.writeheader()
                writer.writerows(self.records)
        print(f"  Results written to {filename}")
        if self.log_file:
            print(f"  Live log written to {self.log_file}")

    def stop(self):
        if not self.tui and not self.gui and self.running:
            print("\nStopping scan...")
        self.running = False


def _estimate_distance(rssi: int, tx_power: Optional[int],
                       env: str = "free_space",
                       ref_rssi: Optional[int] = None) -> Optional[float]:
    """Estimate distance in meters using the log-distance path loss model.

    When *ref_rssi* is provided it is used directly as the expected RSSI at
    the 1-metre reference distance (measured_power), ignoring *tx_power*.
    Otherwise we derive measured_power from *tx_power* by subtracting
    ``_DEFAULT_REF_OFFSET`` (59 dB) — the empirically validated offset used
    by the iBeacon standard that accounts for free-space path loss plus
    typical BLE antenna/enclosure losses.
    """
    if rssi == 0:
        return None
    if ref_rssi is not None:
        measured_power = ref_rssi
    elif tx_power is not None:
        measured_power = tx_power - _DEFAULT_REF_OFFSET
    else:
        return None
    n = _ENV_PATH_LOSS.get(env, 2.0)
    return 10 ** ((measured_power - rssi) / (10 * n))


def _bt_ah(irk: bytes, prand: bytes) -> bytes:
    """Bluetooth Core Spec ah() function (Vol 3, Part H, Section 2.2.2).

    AES-128-ECB(IRK, padding || prand) -> return last 3 bytes.

    Note: ECB mode is mandated by the Bluetooth Core Specification for this
    single-block operation.  It is not a vulnerability — only one 16-byte
    block is ever encrypted, so ECB's lack of diffusion is irrelevant.
    """
    plaintext = b'\x00' * 13 + prand  # 16 bytes: 13 zero-pad + 3-byte prand
    cipher = Cipher(algorithms.AES(irk), modes.ECB())
    enc = cipher.encryptor()
    ct = enc.update(plaintext) + enc.finalize()
    return ct[-3:]  # last 3 bytes = hash


def _is_rpa(addr_bytes: bytes) -> bool:
    """Check if a 6-byte address is a Resolvable Private Address.

    RPA has top two bits of the most-significant byte set to 01.
    """
    return len(addr_bytes) == 6 and (addr_bytes[0] >> 6) == 0b01


def _resolve_rpa(irk: bytes, address: str) -> bool:
    """Resolve a MAC address string against an IRK.

    MAC format: AA:BB:CC:DD:EE:FF
    prand = first 3 octets (AA:BB:CC), hash = last 3 octets (DD:EE:FF).
    Returns True if ah(IRK, prand) == hash.
    """
    parts = address.replace("-", ":").split(":")
    if len(parts) != 6:
        return False
    try:
        addr_bytes = bytes(int(b, 16) for b in parts)
    except ValueError:
        return False
    if not _is_rpa(addr_bytes):
        return False
    prand = addr_bytes[:3]
    expected_hash = addr_bytes[3:]
    return _bt_ah(irk, prand) == expected_hash


def _parse_irk(irk_string: str) -> bytes:
    """Parse an IRK from hex string (plain, colon-separated, or 0x-prefixed).

    Returns 16 bytes or raises ValueError.
    """
    s = irk_string.strip()
    if s.lower().startswith("0x"):
        s = s[2:]
    s = s.replace(":", "").replace("-", "")
    if len(s) != 32:
        raise ValueError(
            f"IRK must be exactly 16 bytes (32 hex chars), got {len(s)} hex chars")
    try:
        return bytes.fromhex(s)
    except ValueError:
        raise ValueError(f"IRK contains invalid hex characters: {irk_string}")


_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")


def main():
    parser = argparse.ArgumentParser(
        description="BLE Scanner — discover all devices or hunt for a specific one"
    )
    parser.add_argument(
        "mac", nargs="?", default=None,
        help="Target MAC address to search for (omit to scan all)"
    )
    parser.add_argument(
        "-a", "--all", action="store_true",
        help="Scan for all broadcasting devices"
    )
    parser.add_argument(
        "--irk", type=str, default=None, metavar="HEX",
        help="Resolve RPAs using this Identity Resolving Key (32 hex chars)"
    )
    parser.add_argument(
        "--irk-file", type=str, default=None, metavar="PATH",
        help="Read IRK(s) from a file (one per line, hex format; "
             "lines starting with # are ignored)"
    )
    parser.add_argument(
        "-t", "--timeout", type=float, default=None,
        help="Scan timeout in seconds (default: 30, or infinite for --irk)"
    )

    # Output / logging
    parser.add_argument(
        "--output", choices=["csv", "json", "jsonl"], default=None,
        help="Batch output format written at end of scan"
    )
    parser.add_argument(
        "-o", "--output-file", type=str, default=None, metavar="FILE",
        help="Output file path (default: btrpa-scan-results.<format>; "
             "use - for stdout)"
    )
    parser.add_argument(
        "--log", type=str, default=None, metavar="FILE",
        help="Stream detections to a CSV file in real time"
    )

    # Verbosity
    verbosity = parser.add_mutually_exclusive_group()
    verbosity.add_argument(
        "-v", "--verbose", action="store_true",
        help="Verbose mode — show additional details"
    )
    verbosity.add_argument(
        "-q", "--quiet", action="store_true",
        help="Quiet mode — suppress per-device output, show summary only"
    )

    # Signal / detection tuning
    parser.add_argument(
        "--min-rssi", type=int, default=None, metavar="DBM",
        help="Minimum RSSI threshold (e.g. -70) — ignore weaker signals"
    )
    parser.add_argument(
        "--rssi-window", type=int, default=1, metavar="N",
        help="RSSI sliding window size for averaging (e.g. 5-10). "
             "Smooths noisy readings for stable distance estimates "
             "(default: 1 = no averaging)"
    )
    parser.add_argument(
        "--active", action="store_true",
        help="Use active scanning — sends SCAN_REQ to get SCAN_RSP with "
             "additional service UUIDs and names (default: passive)"
    )
    parser.add_argument(
        "--environment", choices=["free_space", "indoor", "outdoor"],
        default="free_space",
        help="Environment preset for distance estimation path-loss exponent: "
             "free_space (n=2.0), outdoor (n=2.2), indoor (n=3.0). "
             "Default: free_space"
    )
    parser.add_argument(
        "--ref-rssi", type=int, default=None, metavar="DBM",
        help="Calibrated RSSI (dBm) measured at 1 metre from the target "
             "device. When set, this value is used directly for distance "
             "estimation instead of deriving it from TX Power. "
             "Also enables distance estimates for devices that don't "
             "advertise TX Power"
    )

    # Filtering
    parser.add_argument(
        "--name-filter", type=str, default=None, metavar="PATTERN",
        help="Filter devices by name (case-insensitive substring match)"
    )

    # Proximity alerts
    parser.add_argument(
        "--alert-within", type=float, default=None, metavar="METERS",
        help="Trigger an audible/visual alert when a device is estimated "
             "within this distance (requires TX Power in advertisements)"
    )

    # TUI
    parser.add_argument(
        "--tui", action="store_true",
        help="Live-updating terminal table instead of scrolling output"
    )

    # GUI
    parser.add_argument(
        "--gui", action="store_true",
        help="Launch web-based radar interface in the browser"
    )
    parser.add_argument(
        "--gui-port", type=int, default=5000, metavar="PORT",
        help="Port for GUI web server (default: 5000)"
    )

    # GPS
    parser.add_argument(
        "--no-gps", action="store_true",
        help="Disable GPS location stamping (GPS is on by default via gpsd)"
    )

    # Multi-adapter (Linux)
    parser.add_argument(
        "--adapters", type=str, default=None, metavar="LIST",
        help="Comma-separated Bluetooth adapter names to scan with "
             "(e.g. hci0,hci1 — Linux only)"
    )

    args = parser.parse_args()

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------
    if args.output_file and not args.output:
        parser.error("--output-file (-o) requires --output to specify "
                     "the format (csv, json, or jsonl)")

    if args.mac and not _MAC_RE.match(args.mac):
        parser.error(
            f"Invalid MAC address '{args.mac}'. "
            "Expected format: XX:XX:XX:XX:XX:XX (6 colon-separated hex octets)")

    # Determine if any IRK source was provided
    has_irk = bool(args.irk or args.irk_file or os.environ.get("BTRPA_IRK"))

    if has_irk and args.all:
        parser.error("Cannot use IRK with --all")
    if has_irk and args.mac:
        parser.error("Cannot use IRK with a specific MAC address")
    if args.mac and args.all:
        parser.error("Cannot use --all with a specific MAC address")
    if not args.mac and not args.all and not has_irk:
        print(_BANNER)
        parser.print_help()
        sys.exit(0)

    if args.rssi_window < 1:
        parser.error("--rssi-window must be at least 1")

    if args.tui and not _HAS_CURSES:
        parser.error("--tui requires the 'curses' module "
                     "(install 'windows-curses' on Windows)")

    if args.tui and args.quiet:
        parser.error("Cannot use --tui with --quiet")

    if args.gui and not _HAS_FLASK:
        parser.error("--gui requires Flask and flask-socketio. "
                     "Install with: pip install flask flask-socketio")

    if args.gui and args.tui:
        parser.error("Cannot use --gui with --tui")

    if args.gui and args.quiet:
        parser.error("Cannot use --gui with --quiet")

    if args.irk and args.irk_file:
        parser.error("Cannot use --irk and --irk-file together")

    # Parse IRKs (from --irk, --irk-file, or BTRPA_IRK env var)
    irks: List[bytes] = []
    if args.irk:
        try:
            irks.append(_parse_irk(args.irk))
        except ValueError as e:
            parser.error(str(e))
    elif args.irk_file:
        try:
            with open(args.irk_file) as f:
                for line_num, raw_line in enumerate(f, 1):
                    stripped = raw_line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    try:
                        irks.append(_parse_irk(stripped))
                    except ValueError as e:
                        parser.error(f"IRK file line {line_num}: {e}")
        except OSError as e:
            parser.error(f"Cannot read IRK file: {e}")
        if not irks:
            parser.error("IRK file contains no valid keys")
    elif os.environ.get("BTRPA_IRK"):
        try:
            irks.append(_parse_irk(os.environ["BTRPA_IRK"]))
        except ValueError as e:
            parser.error(f"BTRPA_IRK environment variable: {e}")

    # Default timeout
    if args.timeout is not None:
        timeout = args.timeout
    elif irks or args.gui:
        timeout = float('inf')
    else:
        timeout = 30.0

    # Parse adapters
    adapters = None
    if args.adapters:
        adapters = [a.strip() for a in args.adapters.split(",") if a.strip()]
        if not adapters:
            parser.error("--adapters requires at least one adapter name")

    target = args.mac if not args.all and not irks else None
    scanner = BLEScanner(
        target, timeout, irks=irks,
        output_format=args.output,
        output_file=args.output_file,
        verbose=args.verbose,
        quiet=args.quiet,
        min_rssi=args.min_rssi,
        rssi_window=args.rssi_window,
        active=args.active,
        environment=args.environment,
        alert_within=args.alert_within,
        log_file=args.log,
        tui=args.tui,
        adapters=adapters,
        gps=not args.no_gps,
        ref_rssi=args.ref_rssi,
        name_filter=args.name_filter,
        gui=args.gui,
        gui_port=args.gui_port,
    )

    # On Windows, asyncio doesn't support loop.add_signal_handler, so
    # fall back to the older signal.signal approach.
    if platform.system() == "Windows":
        signal.signal(signal.SIGINT, lambda *_: scanner.stop())

    try:
        asyncio.run(scanner.scan())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
