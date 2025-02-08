"use client";

import React, { useState, useEffect } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar } from 'recharts';
import { Shield, ShieldAlert, Wifi, Clock, Server, Activity, Users, Network, Database } from 'lucide-react';

const IoTMonitor = () => {
  interface Device {
    id: string;
    status: string;
  }

  interface WebSocketState {
    isConnected: boolean;
    error: string | null;
    retryCount: number;
  }
  
  const WS_RETRY_DELAY = 5000;
  const WS_MAX_RETRIES = 5;

  interface BlockchainStats {
    totalBlocks: number;
    verifiedTransactions: number;
    networkNodes: number;
  }

  interface ConnectionStats {
    activeConnections: number;
    totalConnections: number;
    avgConnectionTime: number;
  }

  interface KeyPair {
    deviceId: string;
    publicKey: string;
    nonce: string;
    timestamp: string;
  }
  
  interface BlockchainStorage {
    deviceKeys: { [key: string]: KeyPair };
    nonces: string[];
    lastBlockHash: string;
    transactions: Array<{
      hash: string;
      deviceId: string;
      type: string;
      timestamp: string;
    }>;
  }

  const [wsState, setWsState] = useState<WebSocketState>({
    isConnected: false,
    error: null,
    retryCount: 0,
  });

  // Update the monitorData state to include new properties
  const [monitorData, setMonitorData] = useState<{
    devices: Device[];
    authMetrics: {
      legitimateAuth: number;
      hackerAttempts: number;
      expiredRequests: number;
      replayAttacks: number;
    };
    events: any[];
    blockchainStats: BlockchainStats;
    connectionStats: ConnectionStats;
    blockchainStorage: BlockchainStorage;
  }>({
    devices: [],
    authMetrics: {
      legitimateAuth: 0,
      hackerAttempts: 0,
      expiredRequests: 0,
      replayAttacks: 0,
    },
    events: [],
    blockchainStats: {
      totalBlocks: 0,
      verifiedTransactions: 0,
      networkNodes: 0,
    },
    connectionStats: {
      activeConnections: 0,
      totalConnections: 0,
      avgConnectionTime: 0,
    },
    blockchainStorage: {
      deviceKeys: {},
      nonces: [],
      lastBlockHash: "",
      transactions: [],
    }
  });

  const [connected, setConnected] = useState(false);
  const [connectionError, setConnectionError] = useState<string | null>(null);

  useEffect(() => {
    let ws: WebSocket | null = null;
    let reconnectTimeout: NodeJS.Timeout;

    const connectWebSocket = () => {
      try {
        ws = new WebSocket('ws://localhost:8080/ws');

        // Add WebSocket properties for credentials
        if (ws.url.startsWith('ws://localhost')) {
          (ws as any).credentials = 'include';
      }

        ws.onopen = () => {
          console.log('Connected to IoT Monitor');
          setWsState(prev => ({
            ...prev,
            isConnected: true,
            error: null,
            retryCount: 0,
          }));
        };

        ws.onclose = () => {
          console.log('Disconnected from IoT Monitor');
          setWsState(prev => ({
            ...prev,
            isConnected: false,
            error: "Connection lost. Retrying...",
          }));

          // Attempt to reconnect if under max retries
          if (wsState.retryCount < WS_MAX_RETRIES) {
            reconnectTimeout = setTimeout(() => {
              setWsState(prev => ({
                ...prev,
                retryCount: prev.retryCount + 1,
              }));
              connectWebSocket();
            }, WS_RETRY_DELAY);
          } else {
            setWsState(prev => ({
              ...prev,
              error: "Maximum reconnection attempts reached. Please refresh the page.",
            }));
          }

          // Reset monitor data on disconnect
          setMonitorData({
            devices: [],
            authMetrics: {
              legitimateAuth: 0,
              hackerAttempts: 0,
              expiredRequests: 0,
              replayAttacks: 0,
            },
            events: [],
            blockchainStats: {
              totalBlocks: 0,
              verifiedTransactions: 0,
              networkNodes: 0,
            },
            connectionStats: {
              activeConnections: 0,
              totalConnections: 0,
              avgConnectionTime: 0,
            },
            blockchainStorage: {
              deviceKeys: {},
              nonces: [],
              lastBlockHash: "",
              transactions: []
            }
          });
        };

        ws.onerror = (error) => {
          console.error('WebSocket error:', error);
          setWsState(prev => ({
            ...prev,
            error: 'Failed to connect to IoT Monitor',
          }));
        };

        ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            setMonitorData(prev => ({
              ...prev,
              ...data,
              events: [...(prev.events || []), ...(data.events || [])].slice(-5), // Keep last 100 events
            }));
          } catch (error) {
            console.error('Error parsing WebSocket message:', error);
          }
        };
      } catch (error) {
        console.error('WebSocket connection error:', error);
        setWsState(prev => ({
          ...prev,
          error: 'Failed to establish WebSocket connection',
        }));
      }
    };

    connectWebSocket();

    // Cleanup function
    return () => {
      if (ws) {
        ws.close();
      }
      if (reconnectTimeout) {
        clearTimeout(reconnectTimeout);
      }
    };
  }, []);

  // Calculate auth history data for the line chart
  const authHistory = monitorData.events.reduce((acc: any, event: any) => {
    const hour = new Date(event.timestamp).getHours();
    if (!acc[hour]) {
      acc[hour] = { time: `${hour}:00`, legitimate: 0, failed: 0 };
    }
    if (event.type === 'LegitimateAuth') {
      if (event.success) {
        acc[hour].legitimate++;
      } else {
        acc[hour].failed++;
      }
    }
    return acc;
  }, {});

  const authHistoryData = Object.values(authHistory);

  // Connection status indicator
  const ConnectionStatus = () => (
    <div className="flex flex-col items-end">
      <div className={`flex items-center gap-2 ${wsState.isConnected ? 'text-green-500' : 'text-red-500'}`}>
        <Activity className={`h-4 w-4 ${wsState.isConnected ? 'animate-pulse' : ''}`} />
        <span className="text-sm font-medium">
          {wsState.isConnected ? 'Connected' : 'Disconnected'}
        </span>
      </div>
      {wsState.error && (
        <span className="text-xs text-red-500 mt-1">
          {wsState.error}
          {wsState.retryCount > 0 && ` (Attempt ${wsState.retryCount}/${WS_MAX_RETRIES})`}
        </span>
      )}
    </div>
  );

  const BlockchainStorageSection = () => (
    <Card className="mt-6">
      <CardHeader>
        <CardTitle>Blockchain Storage</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <h3 className="font-medium mb-2">Device Keys</h3>
            <div className="max-h-[200px] overflow-y-auto">
              {Object.values(monitorData.blockchainStorage?.deviceKeys || {}).map((key) => (
                <div key={key.deviceId} className="p-2 bg-gray-50 rounded mb-2">
                  <p className="text-xs font-mono">
                    <span className="font-bold">Device:</span> {key.deviceId}
                  </p>
                  <p className="text-xs font-mono truncate">
                    <span className="font-bold">Key:</span> {key.publicKey}
                  </p>
                  <p className="text-xs font-mono">
                    <span className="font-bold">Nonce:</span> {key.nonce}
                  </p>
                </div>
              ))}
            </div>
          </div>
          <div>
            <h3 className="font-medium mb-2">Recent Transactions</h3>
            <div className="max-h-[200px] overflow-y-auto">
              {(monitorData.blockchainStorage?.transactions || []).map((tx, i) => (
                <div key={i} className="p-2 bg-gray-50 rounded mb-2">
                  <p className="text-xs font-mono truncate">
                    <span className="font-bold">Hash:</span> {tx.hash}
                  </p>
                  <p className="text-xs">
                    <span className="font-bold">Device:</span> {tx.deviceId}
                  </p>
                  <p className="text-xs">
                    <span className="font-bold">Type:</span> {tx.type}
                  </p>
                  <p className="text-xs">
                    <span className="font-bold">Time:</span> {new Date(tx.timestamp).toLocaleString()}
                  </p>
                </div>
              ))}
              {(!monitorData.blockchainStorage?.transactions || monitorData.blockchainStorage.transactions.length === 0) && (
                <div className="text-gray-500 text-sm text-center p-4">
                  No transactions recorded yet
                </div>
              )}
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
  
  // Add device simulation controls
  const DeviceSimulationControls = () => {
    const [deviceCount, setDeviceCount] = useState(1);
    const [error, setError] = useState<string | null>(null);
    const [isLoading, setIsLoading] = useState(false);
  
    function handleSimulation(event: React.MouseEvent<HTMLButtonElement, MouseEvent>): void {
      event.preventDefault();
      setError(null);
      setIsLoading(true);
      
      // Optionally validate deviceCount
      if (deviceCount < 1 || deviceCount > 10) {
      setError("Please choose between 1 and 10 devices.");
      setIsLoading(false);
      return;
      }
      
      // Simulate a delay (e.g., an API call or processing time)
      setTimeout(() => {
      const newDevices = Array.from({ length: deviceCount }, (_, index) => ({
        id: `device-${Date.now()}-${index}`,
        // Randomly decide if the device is authenticated
        status: Math.random() > 0.5 ? "authenticated" : "unauthenticated",
      }));

      // Update the monitorData with the simulated devices appended to the existing ones
      setMonitorData(prev => ({
        ...prev,
        devices: [...prev.devices, ...newDevices]
      }));

      setIsLoading(false);
      }, 1000);
    }

    return (
        <Card className="mt-6">
            <CardHeader>
                <CardTitle>Device Simulation Controls</CardTitle>
            </CardHeader>
            <CardContent>
                <div className="space-y-6">
                    <div className="flex items-center gap-4">
                        <div className="flex items-center gap-2">
                            <label className="text-sm">Number of Devices:</label>
                            <input
                                type="number"
                                min="1"
                                max="10"
                                value={deviceCount}
                                onChange={(e) => setDeviceCount(parseInt(e.target.value))}
                                className="w-20 px-2 py-1 border rounded"
                                disabled={isLoading}
                            />
                        </div>
                        <button
                            onClick={handleSimulation}
                            className={`px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600 disabled:bg-blue-300 disabled:cursor-not-allowed`}
                            disabled={isLoading}
                        >
                            {isLoading ? 'Simulating...' : 'Start Simulation'}
                        </button>
                    </div>
                    {error && (
                        <div className="text-red-500 text-sm">
                            {error}
                        </div>
                    )}
                    
                    {/* Add Simulated Devices Display */}
                    <div className="mt-4">
                        <h3 className="text-sm font-medium mb-2">Simulated Devices</h3>
                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                            {monitorData.devices.map((device, index) => (
                                <div key={device.id} 
                                     className={`p-3 rounded-lg border ${
                                         device.status === "authenticated" 
                                             ? 'border-green-200 bg-green-50' 
                                             : 'border-gray-200 bg-gray-50'
                                     }`}
                                >
                                    <div className="flex items-center justify-between">
                                        <div>
                                            <p className="text-sm font-medium">{device.id}</p>
                                            <p className="text-xs text-gray-500">
                                                Status: {' '}
                                                <span className={`font-medium ${
                                                    device.status === "authenticated" 
                                                        ? 'text-green-600' 
                                                        : 'text-gray-600'
                                                }`}>
                                                    {device.status}
                                                </span>
                                            </p>
                                        </div>
                                        <div className={`h-2 w-2 rounded-full ${
                                            device.status === "authenticated" 
                                                ? 'bg-green-500' 
                                                : 'bg-gray-300'
                                        }`} />
                                    </div>
                                </div>
                            ))}
                        </div>
                        {monitorData.devices.length === 0 && (
                            <div className="text-center text-gray-500 py-4">
                                No devices simulated yet
                            </div>
                        )}
                    </div>
                </div>
            </CardContent>
        </Card>
    );
};

  return (
    <div className="p-6 space-y-6">
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold">IoT Security Monitor</h1>
        <ConnectionStatus />
      </div>

      <DeviceSimulationControls />

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-500">Total Devices</p>
                <p className="text-2xl font-bold">{monitorData.devices.length}</p>
              </div>
              <Server className="h-8 w-8 text-blue-500" />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-500">Auth Success Rate</p>
                <p className="text-2xl font-bold">
                  {monitorData.authMetrics.legitimateAuth > 0
                    ? Math.round(
                        (monitorData.authMetrics.legitimateAuth /
                          Object.values(monitorData.authMetrics).reduce((a, b) => a + b, 0)) *
                          100
                      )
                    : 0}%
                </p>
              </div>
              <Shield className="h-8 w-8 text-green-500" />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-500">Security Alerts</p>
                <p className="text-2xl font-bold">
                  {monitorData.authMetrics.hackerAttempts + monitorData.authMetrics.replayAttacks}
                </p>
              </div>
              <ShieldAlert className="h-8 w-8 text-red-500" />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-500">Active Devices</p>
                <p className="text-2xl font-bold">
                  {monitorData.devices.filter(d => d.status === "authenticated").length}
                </p>
              </div>
              <Wifi className="h-8 w-8 text-purple-500" />
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-6">
  <Card>
    <CardHeader>
      <CardTitle className="text-sm font-medium">Blockchain Network</CardTitle>
    </CardHeader>
    <CardContent>
      <div className="flex items-center justify-between mb-4">
        <Database className="h-8 w-8 text-blue-500" />
        <div className="text-right">
          <p className="text-2xl font-bold">{monitorData.blockchainStats.totalBlocks}</p>
          <p className="text-sm text-gray-500">Total Blocks</p>
        </div>
      </div>
      <div className="space-y-2">
        <div className="flex justify-between">
          <span className="text-sm text-gray-500">Verified Transactions</span>
          <span className="font-medium">{monitorData.blockchainStats.verifiedTransactions}</span>
        </div>
        <div className="flex justify-between">
          <span className="text-sm text-gray-500">Network Nodes</span>
          <span className="font-medium">{monitorData.blockchainStats.networkNodes}</span>
        </div>
      </div>
    </CardContent>
  </Card>

  <Card>
    <CardHeader>
      <CardTitle className="text-sm font-medium">Device Connections</CardTitle>
    </CardHeader>
    <CardContent>
      <div className="flex items-center justify-between mb-4">
        <Users className="h-8 w-8 text-purple-500" />
        <div className="text-right">
          <p className="text-2xl font-bold">{monitorData.connectionStats.activeConnections}</p>
          <p className="text-sm text-gray-500">Active Connections</p>
        </div>
      </div>
      <div className="space-y-2">
        <div className="flex justify-between">
          <span className="text-sm text-gray-500">Total Connections</span>
          <span className="font-medium">{monitorData.connectionStats.totalConnections}</span>
        </div>
        <div className="flex justify-between">
          <span className="text-sm text-gray-500">Avg. Connection Time</span>
          <span className="font-medium">{monitorData.connectionStats.avgConnectionTime}s</span>
        </div>
      </div>
    </CardContent>
  </Card>

  <Card>
    <CardHeader>
      <CardTitle className="text-sm font-medium">Network Status</CardTitle>
    </CardHeader>
    <CardContent>
      <div className="h-[150px]">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={monitorData.events.slice(-10)}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis 
              dataKey="timestamp" 
              tickFormatter={(time) => new Date(time).toLocaleTimeString()} 
            />
            <YAxis />
            <Tooltip />
            <Line 
              type="monotone" 
              dataKey="activeConnections" 
              stroke="#8884d8" 
              name="Active Connections" 
            />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </CardContent>
  </Card>
</div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <CardTitle>Authentication History</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={authHistoryData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="time" />
                  <YAxis />
                  <Tooltip />
                  <Line type="monotone" dataKey="legitimate" stroke="#22c55e" name="Successful" />
                  <Line type="monotone" dataKey="failed" stroke="#ef4444" name="Failed" />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Security Events Distribution</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={[monitorData.authMetrics]}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="name" />
                  <YAxis />
                  <Tooltip />
                  <Bar dataKey="legitimateAuth" fill="#22c55e" name="Legitimate" />
                  <Bar dataKey="hackerAttempts" fill="#ef4444" name="Hacker Attempts" />
                  <Bar dataKey="expiredRequests" fill="#eab308" name="Expired" />
                  <Bar dataKey="replayAttacks" fill="#dc2626" name="Replay Attacks" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Recent Authentication Events</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="relative overflow-x-auto">
            <table className="w-full text-sm text-left text-gray-500">
              <thead className="text-xs text-gray-700 uppercase bg-gray-50">
                <tr>
                  <th className="px-6 py-3">Timestamp</th>
                  <th className="px-6 py-3">Device ID</th>
                  <th className="px-6 py-3">Event Type</th>
                  <th className="px-6 py-3">Status</th>
                </tr>
              </thead>
              <tbody>
                {monitorData.events.slice().reverse().map((event: any, index) => (
                  <tr key={index} className="bg-white border-b">
                    <td className="px-6 py-4">
                      {new Date(event.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="px-6 py-4">{event.deviceId}</td>
                    <td className="px-6 py-4">{event.type}</td>
                    <td className="px-6 py-4">
                      <span className={event.success ? 'text-green-500' : 'text-red-500'}>
                        {event.success ? 'Success' : 'Failed'}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default IoTMonitor;
