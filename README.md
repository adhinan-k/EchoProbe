<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
  <div align="center">
    <h1>🛠️ EchoProbe Installation Guide</h1>
    <img src="Screenshot From 2024-12-28 11-34-23.png" width="800"/>
    <p>Advanced WiFi Monitoring and Attack Detection Tool</p>
    <img src="https://img.shields.io/badge/Python-3.6+-blue.svg"/>
    <img src="https://img.shields.io/badge/License-MIT-green.svg"/>
    <img src="https://img.shields.io/badge/Platform-Linux-orange.svg"/>
  </div>

  <p align="center">
    <a href="#requirements">Requirements</a> •
    <a href="#dependencies">Dependencies</a> •
    <a href="#installation">Installation</a> •
    <a href="#usage">Usage</a> •
    <a href="#troubleshooting">Troubleshooting</a>
  </p>

  <h2 id="requirements">💻 System Requirements</h2>
  <ul>
    <li>Operating System: Linux (Ubuntu/Kali Linux recommended)</li>
    <li>Python 3.6 or higher</li>
    <li>Root privileges</li>
    <li>Compatible wireless adapter with monitor mode support</li>
  </ul>

  <h2 id="dependencies">📦 Dependencies</h2>
  <details>
    <summary>🔧 Core Packages</summary>
    <pre>
    sudo apt-get update
    sudo apt-get upgrade
    sudo apt-get install -y python3 python3-pip aircrack-ng wireless-tools net-tools
    sudo pip3 install scapy
    </pre>
  </details>

  <h2 id="installation">⚙️ Installation</h2>
  <ol>
    <li>Clone the repository:
      <pre>
      git clone https://github.com/adhinan-k/EchoProbe.git
      cd EchoProbe
      chmod +x echoprobe.py
      </pre>
    </li>
    <li>Install required system packages:
      <pre>
      sudo apt-get update && sudo apt-get install -y python3 python3-pip aircrack-ng wireless-tools net-tools
      </pre>
    </li>
  </ol>

  <h2 id="usage">📡 Wireless Adapter Setup</h2>
  <ol>
    <li>Check if your wireless adapter is detected:
      <pre>iwconfig</pre>
    </li>
    <li>Enable monitor mode using airmon-ng:
      <pre>sudo airmon-ng start <wireless-interface></pre>
    </li>
    <li>Run EchoProbe:
      <pre>sudo python3 echoprobe.py</pre>
    </li>
    <li>Stop monitor mode:
      <pre>sudo airmon-ng stop wlan0mon</pre>
    </li>
    <li>Restart NetworkManager:
      <pre>
      sudo service NetworkManager restart
      </pre>
      or
      <pre>
      sudo systemctl restart NetworkManager
      </pre>
    </li>
  </ol>

  <h2>🎯 Recommended Wireless Adapters</h2>
  <table>
    <tr>
      <th>Adapter Model</th>
      <th>Compatibility</th>
    </tr>
    <tr>
      <td>Alfa AWUS036NHA</td>
      <td>✅ Excellent</td>
    </tr>
    <tr>
      <td>TP-Link TL-WN722N (v1)</td>
      <td>✅ Good</td>
    </tr>
    <tr>
      <td>Alfa AWUS036ACH</td>
      <td>✅ Excellent</td>
    </tr>
    <tr>
      <td>Panda PAU09</td>
      <td>✅ Good</td>
    </tr>
  </table>

  <h2>⚠️ Important Notes</h2>
  <ul>
    <li>Some wireless adapters may require additional firmware</li>
    <li>NetworkManager might interfere with monitor mode</li>
    <li>Keep system and packages updated</li>
    <li>Regular testing in monitor mode is recommended</li>
    <li>Always stop monitor mode and restart NetworkManager after using the tool</li>
  </ul>

  <div align="center">
    <h2>🔒 Security Notice</h2>
    <p>Always use this tool responsibly. Obtain necessary permissions before monitoring networks and follow local laws and regulations.</p>
  </div>

  ---

  <div align="center">
    <p>💫 Thank you for choosing EchoProbe! 💫</p>
    <a href="https://github.com/yourusername/echoprobe/stargazers">
      <img src="https://img.shields.io/github/stars/yourusername/echoprobe?style=social"/>
    </a>
  </div>
</body>
</html>
